/**
 * LocalPilot Fleet — Windows Hello for Business (WHfB) & FIDO2 Passwordless Blade
 * dashboard/js/components/whfbTable.js
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

  function getStateBadge(state) {
    const s = String(state || 'ENABLED').toUpperCase();
    if (s === 'ENABLED') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ ENABLED</span>';
    } else if (s === 'DISABLED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🛑 DISABLED</span>';
    }
    return '<span class="badge" style="background:rgba(148,163,184,0.15);color:#94A3B8;font-weight:600;">⭕ NOT CONFIGURED</span>';
  }

  function getComplianceBadge(status) {
    const s = String(status || 'NOT_ENROLLED').toUpperCase();
    if (s === 'COMPLIANT') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ COMPLIANT</span>';
    } else if (s === 'NON_COMPLIANT') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🚨 NON-COMPLIANT</span>';
    } else if (s === 'NOT_ENROLLED') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⏳ NOT ENROLLED</span>';
    }
    return '<span class="badge" style="background:rgba(148,163,184,0.15);color:#94A3B8;font-weight:600;">❓ UNKNOWN</span>';
  }

  function getEventBadge(eventType) {
    const type = String(eventType || 'AUTH_FAILURE').toUpperCase();
    if (type.includes('BLOCKED') || type.includes('SPOOF')) {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">🛡️ ' + esc(type) + '</span>';
    } else if (type.includes('FAILURE')) {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⚠️ ' + esc(type) + '</span>';
    }
    return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:600;">🔑 ' + esc(type) + '</span>';
  }

  function getStatusBadge(status) {
    const s = String(status || 'SUCCESS').toUpperCase();
    if (s === 'SUCCESS') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">SUCCESS</span>';
    } else if (s === 'BLOCKED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">BLOCKED</span>';
    }
    return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">FAILURE</span>';
  }

  async function loadData() {
    const container = document.getElementById('view-whfb');
    if (!container) return;

    container.innerHTML = 
      '<div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">' +
        '<span style="font-size:24px;" class="spin">⏳</span>' +
        '<span>Loading Windows Hello for Business &amp; FIDO2 Posture…</span>' +
      '</div>';

    try {
      const [stats, policiesData, inventoryData, auditData, groupsData] = await Promise.all([
        window.FleetAPI.getWhfbStats().catch(() => ({})),
        window.FleetAPI.getWhfbPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getWhfbInventory().catch(() => ({ inventory: [] })),
        window.FleetAPI.getWhfbAuditLog().catch(() => ({ audit_log: [] })),
        window.FleetAPI.getDynamicGroups ? window.FleetAPI.getDynamicGroups().catch(() => []) : Promise.resolve([])
      ]);

      const policies = policiesData.policies || [];
      const inventory = inventoryData.inventory || [];
      const logs = auditData.audit_log || [];
      const groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

      renderView(container, stats, policies, inventory, logs, groups);
    } catch (err) {
      container.innerHTML = 
        '<div class="error-banner" style="margin:24px;padding:16px;background:rgba(239,68,68,0.1);border-left:4px solid #EF4444;color:#EF4444;">' +
          '<strong>Error loading Windows Hello governance:</strong> ' + esc(err.message) +
        '</div>';
    }
  }

  function renderView(container, stats, policies, inventory, logs, groups) {
    let html = '';

    // Header & Actions
    html += 
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px;">' +
        '<div>' +
          '<h2 style="margin:0 0 4px 0;font-size:1.4rem;font-weight:600;display:flex;align-items:center;gap:8px;">' +
            '<span>🔑</span> Windows Hello for Business &amp; FIDO2 Passwordless' +
          '</h2>' +
          '<p style="margin:0;color:var(--text-muted);font-size:0.85rem;">' +
            'Intune-grade PIN complexity enforcement, TPM 2.0 key attestation, biometric anti-spoofing, and FIDO2 WebAuthn authentication.' +
          '</p>' +
        '</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="intune-btn" id="btn-refresh-whfb" style="display:flex;align-items:center;gap:6px;">' +
            '<span>🔄</span> Refresh' +
          '</button>' +
          '<button class="intune-btn primary" id="btn-create-whfb-policy" style="display:flex;align-items:center;gap:6px;">' +
            '<span>➕</span> Create Policy' +
          '</button>' +
        '</div>' +
      '</div>';

    // 4 KPI Cards
    html += 
      '<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;margin-bottom:24px;">' +
        // Card 1: Audited Workstations
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Audited Workstations' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--text-main, #F8FAFC);margin-bottom:4px;">' +
            (stats.total_audited_devices || 0) + ' <span style="font-size:0.9rem;font-weight:400;color:var(--text-muted);">/ ' + (stats.total_devices_in_fleet || 0) + '</span>' +
          '</div>' +
          '<div style="font-size:0.75rem;color:#10B981;">' +
            '● Active telemetry heartbeats' +
          '</div>' +
        '</div>' +

        // Card 2: Passwordless Enrolled %
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Passwordless Adoption' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:#10B981;margin-bottom:4px;">' +
            (stats.enrolled_pct || 0) + '%' +
          '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' +
            (stats.enrolled_devices_count || 0) + ' workstation(s) enrolled' +
          '</div>' +
        '</div>' +

        // Card 3: Hardware TPM Attested
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Hardware TPM Attested' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:#60A5FA;margin-bottom:4px;">' +
            (stats.tpm_attested_devices_count || 0) +
          '</div>' +
          '<div style="font-size:0.75rem;color:#10B981;">' +
            (stats.compliance_pct || 100) + '% compliance rate' +
          '</div>' +
        '</div>' +

        // Card 4: Biometrics & FIDO2 Active
        '<div class="kpi-card" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;padding:16px;">' +
          '<div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);letter-spacing:0.05em;margin-bottom:8px;">' +
            'Biometrics &amp; FIDO2' +
          '</div>' +
          '<div style="font-size:1.8rem;font-weight:700;color:#A855F7;margin-bottom:4px;">' +
            ((stats.biometrics_active_count || 0) + (stats.fido2_active_count || 0)) +
          '</div>' +
          '<div style="font-size:0.75rem;color:var(--text-muted);">' +
            (stats.biometrics_active_count || 0) + ' Bio | ' + (stats.fido2_active_count || 0) + ' FIDO2' +
          '</div>' +
        '</div>' +
      '</div>';

    // Sub-Navigation Tabs
    html += 
      '<div style="display:flex;border-bottom:1px solid var(--border-color, #334155);margin-bottom:16px;gap:8px;">' +
        '<button class="whfb-tab-btn ' + (currentTab === 'policies' ? 'active' : '') + '" data-tab="policies" style="background:none;border:none;padding:8px 16px;font-size:0.85rem;font-weight:600;cursor:pointer;color:' + (currentTab === 'policies' ? 'var(--primary-color, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'policies' ? 'var(--primary-color, #3B82F6)' : 'transparent') + ';">' +
          '🔑 Windows Hello Policies (' + policies.length + ')' +
        '</button>' +
        '<button class="whfb-tab-btn ' + (currentTab === 'inventory' ? 'active' : '') + '" data-tab="inventory" style="background:none;border:none;padding:8px 16px;font-size:0.85rem;font-weight:600;cursor:pointer;color:' + (currentTab === 'inventory' ? 'var(--primary-color, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'inventory' ? 'var(--primary-color, #3B82F6)' : 'transparent') + ';">' +
          '💻 Workstation Authentication Posture (' + inventory.length + ')' +
        '</button>' +
        '<button class="whfb-tab-btn ' + (currentTab === 'audit' ? 'active' : '') + '" data-tab="audit" style="background:none;border:none;padding:8px 16px;font-size:0.85rem;font-weight:600;cursor:pointer;color:' + (currentTab === 'audit' ? 'var(--primary-color, #3B82F6)' : 'var(--text-muted)') + ';border-bottom:2px solid ' + (currentTab === 'audit' ? 'var(--primary-color, #3B82F6)' : 'transparent') + ';">' +
          '📜 Provisioning &amp; Auth Ledger (' + logs.length + ')' +
        '</button>' +
      '</div>';

    // Content Panels
    if (currentTab === 'policies') {
      html += renderPoliciesTab(policies);
    } else if (currentTab === 'inventory') {
      html += renderInventoryTab(inventory);
    } else {
      html += renderAuditTab(logs);
    }

    container.innerHTML = html;
    attachEvents(container, policies, inventory, logs, groups);
  }

  function renderPoliciesTab(policies) {
    if (!policies || policies.length === 0) {
      return '<div class="empty-state" style="padding:48px;text-align:center;color:var(--text-muted);">No Windows Hello for Business policies configured.</div>';
    }

    let out = 
      '<div class="table-container" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;">' +
          '<thead>' +
            '<tr style="background:rgba(0,0,0,0.2);text-align:left;border-bottom:1px solid var(--border-color, #334155);">' +
              '<th style="padding:10px 14px;">Policy Name</th>' +
              '<th style="padding:10px 14px;">State</th>' +
              '<th style="padding:10px 14px;">Target Group</th>' +
              '<th style="padding:10px 14px;">PIN Length</th>' +
              '<th style="padding:10px 14px;">TPM Attestation</th>' +
              '<th style="padding:10px 14px;">Biometrics</th>' +
              '<th style="padding:10px 14px;">FIDO2 Keys</th>' +
              '<th style="padding:10px 14px;">Assigned</th>' +
              '<th style="padding:10px 14px;text-align:right;">Actions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    for (const p of policies) {
      out += 
        '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
          '<td style="padding:12px 14px;">' +
            '<div style="font-weight:600;color:var(--text-main, #F8FAFC);">' + esc(p.name) + '</div>' +
            '<div style="font-size:0.75rem;color:var(--text-muted);">' + esc(p.description || p.id) + '</div>' +
          '</td>' +
          '<td style="padding:12px 14px;">' + getStateBadge(p.state) + '</td>' +
          '<td style="padding:12px 14px;"><span class="badge" style="background:rgba(59,130,246,0.1);color:#60A5FA;">' + esc(p.target_group_name || p.target_group_id || 'All Devices') + '</span></td>' +
          '<td style="padding:12px 14px;font-family:monospace;font-weight:600;">' + esc(p.min_pin_length) + ' - ' + esc(p.max_pin_length) + ' chars</td>' +
          '<td style="padding:12px 14px;">' + (p.use_tpm_only ? '<span style="color:#10B981;font-weight:600;">🔒 TPM Required</span>' : '<span style="color:var(--text-muted);">Software Allowed</span>') + '</td>' +
          '<td style="padding:12px 14px;">' + (p.allow_biometrics ? (p.require_enhanced_anti_spoofing ? '<span style="color:#10B981;">🛡️ Anti-Spoof</span>' : '<span>✅ Allowed</span>') : '<span style="color:#EF4444;">❌ Blocked</span>') + '</td>' +
          '<td style="padding:12px 14px;">' + (p.allow_fido2_security_keys ? '<span style="color:#A855F7;font-weight:600;">🔑 Enabled</span>' : '<span style="color:var(--text-muted);">Disabled</span>') + '</td>' +
          '<td style="padding:12px 14px;font-weight:600;">' + (p.assigned_devices_count || 0) + '</td>' +
          '<td style="padding:12px 14px;text-align:right;">' +
            '<button class="intune-btn btn-view-whfb-script" data-id="' + esc(p.id) + '" title="View PowerShell Registry Script" style="padding:4px 8px;font-size:0.75rem;margin-right:6px;">📜 Script</button>' +
            '<button class="intune-btn btn-delete-whfb-policy" data-id="' + esc(p.id) + '" title="Delete Policy" style="padding:4px 8px;font-size:0.75rem;color:#EF4444;">🗑️</button>' +
          '</td>' +
        '</tr>';
    }

    out += '</tbody></table></div>';
    return out;
  }

  function renderInventoryTab(inventory) {
    if (!inventory || inventory.length === 0) {
      return '<div class="empty-state" style="padding:48px;text-align:center;color:var(--text-muted);">No workstations have reported Windows Hello authentication telemetry yet.</div>';
    }

    let out = 
      '<div class="table-container" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;">' +
          '<thead>' +
            '<tr style="background:rgba(0,0,0,0.2);text-align:left;border-bottom:1px solid var(--border-color, #334155);">' +
              '<th style="padding:10px 14px;">Workstation</th>' +
              '<th style="padding:10px 14px;">WHfB Enrollment</th>' +
              '<th style="padding:10px 14px;">TPM 2.0 Hardware</th>' +
              '<th style="padding:10px 14px;">Biometrics</th>' +
              '<th style="padding:10px 14px;">FIDO2 Keys</th>' +
              '<th style="padding:10px 14px;">PIN Complexity</th>' +
              '<th style="padding:10px 14px;">Compliance</th>' +
              '<th style="padding:10px 14px;">Last Audited</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    for (const item of inventory) {
      const isEnrolled = item.whfb_enrolled === 1;
      const enrolledBadge = isEnrolled
        ? '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:700;">✅ ENROLLED</span>'
        : '<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-weight:700;">⏳ ' + esc(item.whfb_provisioning_state || 'NOT ENROLLED') + '</span>';

      const tpmBadge = (item.tpm_present && item.tpm_ready)
        ? '<span style="color:#10B981;font-weight:600;">🔒 Present &amp; Ready</span>'
        : (item.tpm_present ? '<span style="color:#F59E0B;">⚠️ Not Ready</span>' : '<span style="color:#EF4444;">❌ Missing</span>');

      let bioStr = '<span style="color:var(--text-muted);">None</span>';
      if (item.face_auth_configured && item.fingerprint_auth_configured) {
        bioStr = '<span style="color:#A855F7;font-weight:600;">👤 Face + 👆 Print</span>';
      } else if (item.face_auth_configured) {
        bioStr = '<span style="color:#60A5FA;font-weight:600;">👤 Face' + (item.anti_spoofing_active ? ' (Anti-Spoof)' : '') + '</span>';
      } else if (item.fingerprint_auth_configured) {
        bioStr = '<span style="color:#60A5FA;font-weight:600;">👆 Fingerprint</span>';
      }

      out += 
        '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
          '<td style="padding:12px 14px;">' +
            '<div style="font-weight:600;color:var(--text-main, #F8FAFC);">' + esc(item.hostname) + '</div>' +
            '<div style="font-size:0.75rem;color:var(--text-muted);">' + esc(item.device_ip || 'Unknown IP') + '</div>' +
          '</td>' +
          '<td style="padding:12px 14px;">' + enrolledBadge + '</td>' +
          '<td style="padding:12px 14px;">' + tpmBadge + '</td>' +
          '<td style="padding:12px 14px;">' + bioStr + '</td>' +
          '<td style="padding:12px 14px;font-weight:600;">' + (item.fido2_keys_count > 0 ? ('🔑 ' + item.fido2_keys_count + ' key(s)') : '<span style="color:var(--text-muted);">0</span>') + '</td>' +
          '<td style="padding:12px 14px;">' + (item.pin_complexity_compliant ? '<span style="color:#10B981;font-weight:600;">✅ Compliant</span>' : '<span style="color:#EF4444;font-weight:700;">🚨 Violates Rules</span>') + '</td>' +
          '<td style="padding:12px 14px;">' + getComplianceBadge(item.compliance_status) + '</td>' +
          '<td style="padding:12px 14px;color:var(--text-muted);font-size:0.75rem;">' + esc(item.last_audit_at || 'Just now') + '</td>' +
        '</tr>';
    }

    out += '</tbody></table></div>';
    return out;
  }

  function renderAuditTab(logs) {
    if (!logs || logs.length === 0) {
      return '<div class="empty-state" style="padding:48px;text-align:center;color:var(--text-muted);">No Windows Hello or FIDO2 authentication events recorded yet.</div>';
    }

    let out = 
      '<div class="table-container" style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;overflow-x:auto;">' +
        '<table class="intune-table" style="width:100%;border-collapse:collapse;font-size:0.85rem;">' +
          '<thead>' +
            '<tr style="background:rgba(0,0,0,0.2);text-align:left;border-bottom:1px solid var(--border-color, #334155);">' +
              '<th style="padding:10px 14px;">Timestamp</th>' +
              '<th style="padding:10px 14px;">Workstation</th>' +
              '<th style="padding:10px 14px;">Event Type</th>' +
              '<th style="padding:10px 14px;">Credential</th>' +
              '<th style="padding:10px 14px;">User</th>' +
              '<th style="padding:10px 14px;">Status</th>' +
              '<th style="padding:10px 14px;">Details</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>';

    for (const log of logs) {
      out += 
        '<tr style="border-bottom:1px solid var(--border-color, #334155);">' +
          '<td style="padding:12px 14px;white-space:nowrap;color:var(--text-muted);font-size:0.75rem;">' + esc(log.timestamp) + '</td>' +
          '<td style="padding:12px 14px;font-weight:600;">' + esc(log.hostname || log.device_id) + '</td>' +
          '<td style="padding:12px 14px;">' + getEventBadge(log.event_type) + '</td>' +
          '<td style="padding:12px 14px;font-family:monospace;font-weight:600;">' + esc(log.credential_type) + '</td>' +
          '<td style="padding:12px 14px;font-weight:500;">' + esc(log.user_name || 'System') + '</td>' +
          '<td style="padding:12px 14px;">' + getStatusBadge(log.status) + '</td>' +
          '<td style="padding:12px 14px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-muted);font-size:0.8rem;" title="' + esc(log.details) + '">' +
            esc(log.details) +
          '</td>' +
        '</tr>';
    }

    out += '</tbody></table></div>';
    return out;
  }

  function attachEvents(container, policies, inventory, logs, groups) {
    // Refresh Button
    const refreshBtn = container.querySelector('#btn-refresh-whfb');
    if (refreshBtn) {
      refreshBtn.onclick = () => loadData();
    }

    // Sub-tab switcher
    container.querySelectorAll('.whfb-tab-btn').forEach(btn => {
      btn.onclick = () => {
        currentTab = btn.getAttribute('data-tab');
        loadData();
      };
    });

    // Create Policy Button
    const createBtn = container.querySelector('#btn-create-whfb-policy');
    if (createBtn) {
      createBtn.onclick = () => showCreatePolicyModal(groups);
    }

    // View Script Buttons
    container.querySelectorAll('.btn-view-whfb-script').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        try {
          const res = await window.FleetAPI.getWhfbPolicy(id);
          if (res && res.script) {
            showScriptModal(res.policy.name, res.script);
          }
        } catch (e) {
          alert('Failed to load policy script: ' + e.message);
        }
      };
    });

    // Delete Policy Buttons
    container.querySelectorAll('.btn-delete-whfb-policy').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-id');
        if (confirm('Delete Windows Hello policy [' + id + ']? Workstations will revert to baseline.')) {
          try {
            await window.FleetAPI.deleteWhfbPolicy(id);
            loadData();
          } catch (e) {
            alert('Failed to delete policy: ' + e.message);
          }
        }
      };
    });
  }

  function showScriptModal(policyName, scriptContent) {
    let overlay = document.getElementById('whfb-modal-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'whfb-modal-overlay';
      overlay.style.position = 'fixed';
      overlay.style.top = '0';
      overlay.style.left = '0';
      overlay.style.width = '100vw';
      overlay.style.height = '100vh';
      overlay.style.background = 'rgba(0,0,0,0.7)';
      overlay.style.display = 'flex';
      overlay.style.alignItems = 'center';
      overlay.style.justifyContent = 'center';
      overlay.style.zIndex = '9999';
      document.body.appendChild(overlay);
    }

    overlay.innerHTML = 
      '<div style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;max-width:700px;width:90%;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">' +
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border-color, #334155);display:flex;justify-content:space-between;align-items:center;">' +
          '<h3 style="margin:0;font-size:1.1rem;font-weight:600;display:flex;align-items:center;gap:8px;">' +
            '<span>📜</span> PowerShell Registry Script: ' + esc(policyName) +
          '</h3>' +
          '<button id="btn-close-whfb-modal" style="background:none;border:none;font-size:1.4rem;color:var(--text-muted);cursor:pointer;">&times;</button>' +
        '</div>' +
        '<div style="padding:20px;overflow-y:auto;flex:1;">' +
          '<pre style="margin:0;background:#0F172A;color:#38BDF8;padding:16px;border-radius:6px;font-family:monospace;font-size:0.8rem;white-space:pre-wrap;line-height:1.4;">' +
            esc(scriptContent) +
          '</pre>' +
        '</div>' +
        '<div style="padding:12px 20px;border-top:1px solid var(--border-color, #334155);display:flex;justify-content:flex-end;gap:8px;">' +
          '<button class="intune-btn" id="btn-copy-whfb-script">📋 Copy Script</button>' +
          '<button class="intune-btn primary" id="btn-done-whfb-script">Done</button>' +
        '</div>' +
      '</div>';

    overlay.style.display = 'flex';
    const close = () => { overlay.style.display = 'none'; };
    overlay.querySelector('#btn-close-whfb-modal').onclick = close;
    overlay.querySelector('#btn-done-whfb-script').onclick = close;
    overlay.querySelector('#btn-copy-whfb-script').onclick = () => {
      navigator.clipboard.writeText(scriptContent).then(() => alert('PowerShell script copied to clipboard!'));
    };
  }

  function showCreatePolicyModal(groups) {
    let overlay = document.getElementById('whfb-modal-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'whfb-modal-overlay';
      overlay.style.position = 'fixed';
      overlay.style.top = '0';
      overlay.style.left = '0';
      overlay.style.width = '100vw';
      overlay.style.height = '100vh';
      overlay.style.background = 'rgba(0,0,0,0.7)';
      overlay.style.display = 'flex';
      overlay.style.alignItems = 'center';
      overlay.style.justifyContent = 'center';
      overlay.style.zIndex = '9999';
      document.body.appendChild(overlay);
    }

    let groupOptions = '<option value="grp-all">All Devices (grp-all)</option>';
    if (Array.isArray(groups)) {
      for (const g of groups) {
        if (g.id !== 'grp-all') {
          groupOptions += '<option value="' + esc(g.id) + '">' + esc(g.name) + ' (' + esc(g.id) + ')</option>';
        }
      }
    }

    overlay.innerHTML = 
      '<div style="background:var(--card-bg, #1E293B);border:1px solid var(--border-color, #334155);border-radius:8px;max-width:640px;width:90%;max-height:90vh;display:flex;flex-direction:column;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">' +
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border-color, #334155);display:flex;justify-content:space-between;align-items:center;">' +
          '<h3 style="margin:0;font-size:1.1rem;font-weight:600;display:flex;align-items:center;gap:8px;">' +
            '<span>➕</span> Create Windows Hello &amp; FIDO2 Policy' +
          '</h3>' +
          '<button id="btn-close-whfb-create" style="background:none;border:none;font-size:1.4rem;color:var(--text-muted);cursor:pointer;">&times;</button>' +
        '</div>' +
        '<div style="padding:20px;overflow-y:auto;flex:1;">' +
          '<div style="margin-bottom:16px;">' +
            '<label style="display:block;font-size:0.75rem;font-weight:600;text-transform:uppercase;color:var(--text-muted);margin-bottom:6px;">Quick Presets</label>' +
            '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
              '<button type="button" class="intune-btn" id="preset-whfb-strict" style="font-size:0.75rem;">🏢 Zero-Trust Passwordless</button>' +
              '<button type="button" class="intune-btn" id="preset-whfb-workstation" style="font-size:0.75rem;">💻 Standard Workstation</button>' +
              '<button type="button" class="intune-btn" id="preset-whfb-kiosk" style="font-size:0.75rem;">🚫 Kiosk Lockout</button>' +
            '</div>' +
          '</div>' +
          '<form id="form-create-whfb">' +
            '<div style="margin-bottom:12px;">' +
              '<label style="display:block;font-size:0.8rem;font-weight:600;margin-bottom:4px;">Policy Name *</label>' +
              '<input type="text" id="whfb-name" required class="intune-input" style="width:100%;padding:8px;border-radius:4px;border:1px solid var(--border-color, #334155);background:var(--input-bg, #0F172A);color:var(--text-main, #F8FAFC);box-sizing:border-box;" placeholder="e.g. Enterprise Passwordless Standard">' +
            '</div>' +
            '<div style="margin-bottom:12px;">' +
              '<label style="display:block;font-size:0.8rem;font-weight:600;margin-bottom:4px;">Description</label>' +
              '<input type="text" id="whfb-desc" class="intune-input" style="width:100%;padding:8px;border-radius:4px;border:1px solid var(--border-color, #334155);background:var(--input-bg, #0F172A);color:var(--text-main, #F8FAFC);box-sizing:border-box;" placeholder="Purpose of this policy">' +
            '</div>' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">' +
              '<div>' +
                '<label style="display:block;font-size:0.8rem;font-weight:600;margin-bottom:4px;">Target Device Group</label>' +
                '<select id="whfb-group" style="width:100%;padding:8px;border-radius:4px;border:1px solid var(--border-color, #334155);background:var(--input-bg, #0F172A);color:var(--text-main, #F8FAFC);">' +
                  groupOptions +
                '</select>' +
              '</div>' +
              '<div>' +
                '<label style="display:block;font-size:0.8rem;font-weight:600;margin-bottom:4px;">Policy State</label>' +
                '<select id="whfb-state" style="width:100%;padding:8px;border-radius:4px;border:1px solid var(--border-color, #334155);background:var(--input-bg, #0F172A);color:var(--text-main, #F8FAFC);">' +
                  '<option value="ENABLED">ENABLED</option>' +
                  '<option value="DISABLED">DISABLED</option>' +
                '</select>' +
              '</div>' +
            '</div>' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">' +
              '<div>' +
                '<label style="display:block;font-size:0.8rem;font-weight:600;margin-bottom:4px;">Min PIN Length</label>' +
                '<input type="number" id="whfb-min-pin" value="6" min="4" max="127" style="width:100%;padding:8px;border-radius:4px;border:1px solid var(--border-color, #334155);background:var(--input-bg, #0F172A);color:var(--text-main, #F8FAFC);box-sizing:border-box;">' +
              '</div>' +
              '<div>' +
                '<label style="display:block;font-size:0.8rem;font-weight:600;margin-bottom:4px;">Max PIN Length</label>' +
                '<input type="number" id="whfb-max-pin" value="127" min="6" max="127" style="width:100%;padding:8px;border-radius:4px;border:1px solid var(--border-color, #334155);background:var(--input-bg, #0F172A);color:var(--text-main, #F8FAFC);box-sizing:border-box;">' +
              '</div>' +
            '</div>' +
            '<div style="margin-bottom:16px;background:rgba(0,0,0,0.2);padding:12px;border-radius:6px;">' +
              '<div style="font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">Security Controls</div>' +
              '<div style="display:flex;flex-direction:column;gap:8px;font-size:0.85rem;">' +
                '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;">' +
                  '<input type="checkbox" id="whfb-tpm-only" checked> <span>Mandate Hardware TPM 2.0 (No software fallback)</span>' +
                '</label>' +
                '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;">' +
                  '<input type="checkbox" id="whfb-allow-bio" checked> <span>Allow Biometric Sign-in (Face &amp; Fingerprint)</span>' +
                '</label>' +
                '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;">' +
                  '<input type="checkbox" id="whfb-anti-spoof" checked> <span>Require Enhanced Anti-Spoofing (IR Depth Camera)</span>' +
                '</label>' +
                '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;">' +
                  '<input type="checkbox" id="whfb-fido2" checked> <span>Enable FIDO2 / WebAuthn Security Key Sign-in</span>' +
                '</label>' +
              '</div>' +
            '</div>' +
            '<div style="display:flex;justify-content:flex-end;gap:8px;">' +
              '<button type="button" class="intune-btn" id="btn-cancel-whfb-create">Cancel</button>' +
              '<button type="submit" class="intune-btn primary">Create Policy</button>' +
            '</div>' +
          '</form>' +
        '</div>' +
      '</div>';

    overlay.style.display = 'flex';
    const close = () => { overlay.style.display = 'none'; };
    overlay.querySelector('#btn-close-whfb-create').onclick = close;
    overlay.querySelector('#btn-cancel-whfb-create').onclick = close;

    // Presets
    overlay.querySelector('#preset-whfb-strict').onclick = () => {
      overlay.querySelector('#whfb-name').value = 'Enterprise Zero-Trust Passwordless WHfB';
      overlay.querySelector('#whfb-desc').value = 'Mandates TPM 2.0, 8+ char PIN, Biometric Anti-Spoofing, and FIDO2 keys';
      overlay.querySelector('#whfb-state').value = 'ENABLED';
      overlay.querySelector('#whfb-min-pin').value = 8;
      overlay.querySelector('#whfb-tpm-only').checked = true;
      overlay.querySelector('#whfb-allow-bio').checked = true;
      overlay.querySelector('#whfb-anti-spoof').checked = true;
      overlay.querySelector('#whfb-fido2').checked = true;
    };

    overlay.querySelector('#preset-whfb-workstation').onclick = () => {
      overlay.querySelector('#whfb-name').value = 'Standard Workstation PIN & Biometrics';
      overlay.querySelector('#whfb-desc').value = 'Standard 6-digit PIN with biometrics allowed';
      overlay.querySelector('#whfb-state').value = 'ENABLED';
      overlay.querySelector('#whfb-min-pin').value = 6;
      overlay.querySelector('#whfb-tpm-only').checked = false;
      overlay.querySelector('#whfb-allow-bio').checked = true;
      overlay.querySelector('#whfb-anti-spoof').checked = false;
      overlay.querySelector('#whfb-fido2').checked = true;
    };

    overlay.querySelector('#preset-whfb-kiosk').onclick = () => {
      overlay.querySelector('#whfb-name').value = 'Kiosk & Exam Lockout Policy';
      overlay.querySelector('#whfb-desc').value = 'Disables Windows Hello enrollment on shared terminals';
      overlay.querySelector('#whfb-state').value = 'DISABLED';
      overlay.querySelector('#whfb-min-pin').value = 6;
      overlay.querySelector('#whfb-tpm-only').checked = false;
      overlay.querySelector('#whfb-allow-bio').checked = false;
      overlay.querySelector('#whfb-anti-spoof').checked = false;
      overlay.querySelector('#whfb-fido2').checked = false;
    };

    // Form Submit
    overlay.querySelector('#form-create-whfb').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        name: overlay.querySelector('#whfb-name').value.trim(),
        description: overlay.querySelector('#whfb-desc').value.trim(),
        target_group_id: overlay.querySelector('#whfb-group').value,
        state: overlay.querySelector('#whfb-state').value,
        min_pin_length: Number(overlay.querySelector('#whfb-min-pin').value),
        max_pin_length: Number(overlay.querySelector('#whfb-max-pin').value),
        use_tpm_only: overlay.querySelector('#whfb-tpm-only').checked ? 1 : 0,
        allow_biometrics: overlay.querySelector('#whfb-allow-bio').checked ? 1 : 0,
        require_enhanced_anti_spoofing: overlay.querySelector('#whfb-anti-spoof').checked ? 1 : 0,
        allow_fido2_security_keys: overlay.querySelector('#whfb-fido2').checked ? 1 : 0
      };

      try {
        await window.FleetAPI.createWhfbPolicy(payload);
        close();
        loadData();
      } catch (err) {
        alert('Failed to create policy: ' + err.message);
      }
    };
  }

  window.WhfbTable = {
    init: loadData
  };
})();
