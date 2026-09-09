/**
 * LocalPilot Fleet — Organizational Messages & Toast Notifications Blade
 * dashboard/js/components/messagesTable.js
 */

(function () {
  'use strict';

  let currentTab = 'campaigns'; // 'campaigns' | 'deliveries'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getThemeBadge(theme) {
    const map = {
      CRITICAL: { bg: 'rgba(239,68,68,0.2)', text: '#EF4444' },
      WARNING: { bg: 'rgba(245,158,11,0.2)', text: '#F59E0B' },
      UPDATE: { bg: 'rgba(59,130,246,0.2)', text: '#60A5FA' },
      ONBOARDING: { bg: 'rgba(16,185,129,0.2)', text: '#10B981' },
      INFO: { bg: 'rgba(148,163,184,0.2)', text: '#94A3B8' }
    };
    const c = map[theme] || map.INFO;
    return `<span class="badge" style="background:${c.bg};color:${c.text};font-weight:600;">${esc(theme)}</span>`;
  }

  function getSurfaceBadge(surface) {
    const icon = surface === 'TOAST' ? '🍞' : (surface === 'TASKBAR' ? '📌' : '🪟');
    return `<span class="badge" style="background:rgba(255,255,255,0.06);color:var(--text-primary);">${icon} ${esc(surface)}</span>`;
  }

  async function loadData() {
    const container = document.getElementById('view-messages');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">
        <span style="font-size:24px;" class="spin">⏳</span>
        <span>Loading Organizational Messages &amp; Toast Campaigns…</span>
      </div>
    `;

    try {
      const [stats, messagesData, deliveriesData, groupsData] = await Promise.all([
        window.FleetAPI.getMessageStats().catch(() => ({})),
        window.FleetAPI.getMessages().catch(() => ({ messages: [] })),
        window.FleetAPI.getMessageDeliveries({ limit: 50 }).catch(() => ({ deliveries: [] })),
        window.FleetAPI.getDynamicGroups ? window.FleetAPI.getDynamicGroups().catch(() => ({ groups: [] })) : Promise.resolve({ groups: [] })
      ]);

      renderBlade(container, {
        stats,
        messages: messagesData.messages || [],
        deliveries: deliveriesData.deliveries || [],
        groups: groupsData.groups || []
      });
    } catch (err) {
      container.innerHTML = `
        <div style="padding:24px;color:#EF4444;">
          <h3>Failed to load Organizational Messages</h3>
          <p>${esc(err.message)}</p>
        </div>
      `;
    }
  }

  function renderBlade(container, data) {
    const s = data.stats || {};

    const html = `
      <div class="blade-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
        <div>
          <h2 style="margin:0;font-size:20px;font-weight:600;color:var(--text-primary);">📢 Organizational Messages</h2>
          <p style="margin:4px 0 0;font-size:13px;color:var(--text-muted);">
            Deliver branded, targeted native Windows toast notifications, taskbar alerts, and IT announcements directly to managed workstations.
          </p>
        </div>
        <div style="display:flex;gap:10px;">
          <button class="intune-btn primary" id="btn-create-message">+ Create Message</button>
          <button class="intune-btn" id="btn-send-quick-toast">⚡ Send Quick Toast</button>
          <button class="intune-btn" id="btn-refresh-messages">↻ Refresh</button>
        </div>
      </div>

      <!-- ── KPI Cards Strip ── -->
      <div class="kpi-grid" style="display:grid;grid-template-columns:repeat(4, 1fr);gap:16px;margin-bottom:24px;">
        <div class="kpi-card" style="border-left:4px solid #3B82F6;background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Message Catalog</div>
          <div style="font-size:28px;font-weight:700;color:var(--text-primary);margin-top:6px;">${s.total_messages || 0}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">${s.active_messages || 0} active campaign(s)</div>
        </div>

        <div class="kpi-card" style="border-left:4px solid #10B981;background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Active Campaigns</div>
          <div style="font-size:28px;font-weight:700;color:#10B981;margin-top:6px;">${s.active_messages || 0}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">Targeting fleet device groups</div>
        </div>

        <div class="kpi-card" style="border-left:4px solid #8B5CF6;background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Fleet Deliveries</div>
          <div style="font-size:28px;font-weight:700;color:#8B5CF6;margin-top:6px;">${s.total_deliveries || 0}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">${s.delivered_count || 0} confirmed delivered</div>
        </div>

        <div class="kpi-card" style="border-left:4px solid #F59E0B;background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Engagement Rate</div>
          <div style="font-size:28px;font-weight:700;color:#F59E0B;margin-top:6px;">${s.engagement_rate_percent || 0}%</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">${s.actioned_count || 0} clicked or acknowledged</div>
        </div>
      </div>

      <!-- ── Sub-tabs Navigation ── -->
      <div class="sub-tab-bar" style="display:flex;gap:4px;border-bottom:1px solid #334155;margin-bottom:20px;">
        <button class="sub-tab-btn ${currentTab === 'campaigns' ? 'active' : ''}" data-subtab="campaigns">
          📢 Message Campaigns (${data.messages.length})
        </button>
        <button class="sub-tab-btn ${currentTab === 'deliveries' ? 'active' : ''}" data-subtab="deliveries">
          📋 Delivery &amp; Interaction Audit Log (${data.deliveries.length})
        </button>
      </div>

      <!-- ── Tab Content Container ── -->
      <div id="messages-subtab-content"></div>
    `;

    container.innerHTML = html;

    // Attach subtab click events
    container.querySelectorAll('.sub-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        currentTab = btn.getAttribute('data-subtab');
        renderBlade(container, data);
      });
    });

    // Render active subtab
    const content = container.querySelector('#messages-subtab-content');
    if (currentTab === 'campaigns') {
      renderCampaignsTab(content, data.messages, data.groups);
    } else {
      renderDeliveriesTab(content, data.deliveries);
    }

    // Attach action listeners
    container.querySelector('#btn-refresh-messages')?.addEventListener('click', loadData);
    container.querySelector('#btn-create-message')?.addEventListener('click', () => showMessageModal(null, data.groups));
    container.querySelector('#btn-send-quick-toast')?.addEventListener('click', showQuickToastModal);
  }

  function renderCampaignsTab(el, messages, groups) {
    if (!messages || messages.length === 0) {
      el.innerHTML = `
        <div style="padding:36px;text-align:center;background:#1e293b;border-radius:8px;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">📢</div>
          <div style="font-size:15px;font-weight:600;color:var(--text-primary);">No Organizational Messages Configured</div>
          <div style="font-size:13px;margin-top:4px;">Click "+ Create Message" above to broadcast notifications to fleet devices.</div>
        </div>
      `;
      return;
    }

    let rowsHtml = '';
    messages.forEach(m => {
      const isEnabled = m.enabled;
      const statusPill = isEnabled
        ? `<span class="status-pill" style="color:#10b981;border-color:#10b981;">Active</span>`
        : `<span class="status-pill" style="color:#94a3b8;border-color:#334155;">Disabled</span>`;

      rowsHtml += `
        <tr>
          <td>
            <div style="font-weight:600;color:var(--text-primary);font-size:13px;">${esc(m.title)}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${esc(m.message_body.substring(0, 75))}${m.message_body.length > 75 ? '…' : ''}</div>
          </td>
          <td>${getSurfaceBadge(m.surface)}</td>
          <td>${getThemeBadge(m.theme)}</td>
          <td><span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;">${esc(m.target_group_name)}</span></td>
          <td style="font-size:12px;">${esc(m.frequency)}</td>
          <td style="font-size:12px;">${m.delivered_count} / ${m.total_deliveries}</td>
          <td>${statusPill}</td>
          <td>
            <div style="display:flex;gap:6px;">
              <button class="intune-btn small btn-edit-msg" data-msg-id="${esc(m.id)}">✏️ Edit</button>
              <button class="intune-btn small btn-delete-msg" data-msg-id="${esc(m.id)}" style="color:#EF4444;">🗑️</button>
            </div>
          </td>
        </tr>
      `;
    });

    el.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="border-bottom:1px solid #334155;text-align:left;font-size:12px;color:var(--text-muted);">
              <th style="padding:12px 16px;">Message Title &amp; Description</th>
              <th style="padding:12px 16px;">Surface</th>
              <th style="padding:12px 16px;">Theme</th>
              <th style="padding:12px 16px;">Target Group</th>
              <th style="padding:12px 16px;">Frequency</th>
              <th style="padding:12px 16px;">Deliveries</th>
              <th style="padding:12px 16px;">Status</th>
              <th style="padding:12px 16px;">Actions</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;

    el.querySelectorAll('.btn-edit-msg').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-msg-id');
        try {
          const msg = await window.FleetAPI.getMessage(id);
          showMessageModal(msg, groups);
        } catch (err) {
          alert(`Failed to fetch message: ${err.message}`);
        }
      });
    });

    el.querySelectorAll('.btn-delete-msg').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-msg-id');
        if (!confirm('Are you sure you want to delete this organizational message?')) return;
        try {
          await window.FleetAPI.deleteMessage(id);
          if (typeof showToast === 'function') showToast('Message Deleted', 'Organizational message removed from fleet catalog.', 'info');
          loadData();
        } catch (err) {
          alert(`Failed to delete message: ${err.message}`);
        }
      });
    });
  }

  function renderDeliveriesTab(el, deliveries) {
    if (!deliveries || deliveries.length === 0) {
      el.innerHTML = `
        <div style="padding:36px;text-align:center;background:#1e293b;border-radius:8px;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">📬</div>
          <div style="font-size:15px;font-weight:600;color:var(--text-primary);">No Deliveries Recorded Yet</div>
          <div style="font-size:13px;margin-top:4px;">Messages delivered to nodes during heartbeat cycles will appear here.</div>
        </div>
      `;
      return;
    }

    let rowsHtml = '';
    deliveries.forEach(d => {
      const statusColor = d.status === 'ACTIONED' ? '#10B981' : (d.status === 'DELIVERED' ? '#3B82F6' : '#94A3B8');
      rowsHtml += `
        <tr>
          <td style="font-weight:600;color:var(--text-primary);">${esc(d.hostname)}</td>
          <td>${esc(d.message_title)}</td>
          <td>${getSurfaceBadge(d.surface)}</td>
          <td><span class="status-pill" style="color:${statusColor};border-color:${statusColor};font-size:11px;">${esc(d.status)}</span></td>
          <td style="font-size:12px;color:var(--text-muted);">${d.delivered_at ? new Date(d.delivered_at).toLocaleString() : 'Pending sync'}</td>
          <td style="font-size:12px;color:var(--text-muted);">${d.interacted_at ? new Date(d.interacted_at).toLocaleString() : '—'}</td>
        </tr>
      `;
    });

    el.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="border-bottom:1px solid #334155;text-align:left;font-size:12px;color:var(--text-muted);">
              <th style="padding:12px 16px;">Target Hostname</th>
              <th style="padding:12px 16px;">Message</th>
              <th style="padding:12px 16px;">Surface</th>
              <th style="padding:12px 16px;">Delivery Posture</th>
              <th style="padding:12px 16px;">Delivered At</th>
              <th style="padding:12px 16px;">User Interacted</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;
  }

  function showMessageModal(msg = null, groups = []) {
    const isEdit = Boolean(msg && msg.id);

    let modal = document.getElementById('message-campaign-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'message-campaign-modal';
      modal.className = 'modal-backdrop';
      document.body.appendChild(modal);
    }

    const groupOptions = `
      <option value="grp-all" ${!msg || msg.target_group_id === 'grp-all' ? 'selected' : ''}>All Devices (grp-all)</option>
      ${groups.map(g => `<option value="${esc(g.id)}" ${msg && msg.target_group_id === g.id ? 'selected' : ''}>${esc(g.name)} (${esc(g.id)})</option>`).join('')}
    `;

    modal.innerHTML = `
      <div class="modal-card" style="max-width:620px;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px;max-height:90vh;overflow-y:auto;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:17px;color:var(--text-primary);">${isEdit ? '✏️ Edit Organizational Message' : '📢 Create Organizational Message'}</h3>
          <button class="close-btn" id="btn-close-msg-modal" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;">✕</button>
        </div>

        <!-- Enterprise Quick Presets -->
        ${!isEdit ? `
          <div style="background:#1e293b;border:1px dashed #3B82F6;border-radius:6px;padding:12px;margin-bottom:16px;">
            <div style="font-size:11px;font-weight:600;color:#60A5FA;text-transform:uppercase;margin-bottom:8px;">Enterprise Quick Presets</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button class="intune-btn small preset-btn" data-preset="reboot">🚨 Patch Reboot Toast</button>
              <button class="intune-btn small preset-btn" data-preset="onboarding">👋 Workstation Onboarding</button>
              <button class="intune-btn small preset-btn" data-preset="antivirus">🛡️ Antivirus Advisory</button>
            </div>
          </div>
        ` : ''}

        <div style="display:flex;flex-direction:column;gap:14px;">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">MESSAGE TITLE</label>
            <input id="modal-msg-title" class="intune-input" type="text" style="width:100%;box-sizing:border-box;" placeholder="e.g. Windows Updates Required" value="${esc(msg?.title || '')}">
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">MESSAGE BODY</label>
            <textarea id="modal-msg-body" class="intune-input" rows="3" style="width:100%;box-sizing:border-box;font-family:inherit;" placeholder="Clear instruction or notification for the device user...">${esc(msg?.message_body || '')}</textarea>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">SURFACE AREA</label>
              <select id="modal-msg-surface" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="TOAST" ${msg?.surface === 'TOAST' ? 'selected' : ''}>🍞 Native Windows Toast</option>
                <option value="TASKBAR" ${msg?.surface === 'TASKBAR' ? 'selected' : ''}>📌 Taskbar / Tray Notification</option>
                <option value="MODAL" ${msg?.surface === 'MODAL' ? 'selected' : ''}>🪟 Full Desktop Modal</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">THEME &amp; SEVERITY</label>
              <select id="modal-msg-theme" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="INFO" ${msg?.theme === 'INFO' ? 'selected' : ''}>ℹ️ Informational (Blue)</option>
                <option value="WARNING" ${msg?.theme === 'WARNING' ? 'selected' : ''}>⚠️ Warning (Amber)</option>
                <option value="CRITICAL" ${msg?.theme === 'CRITICAL' ? 'selected' : ''}>🚨 Critical / Security (Red)</option>
                <option value="UPDATE" ${msg?.theme === 'UPDATE' ? 'selected' : ''}>🔄 Windows Update</option>
                <option value="ONBOARDING" ${msg?.theme === 'ONBOARDING' ? 'selected' : ''}>✨ Onboarding (Green)</option>
              </select>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">TARGET DEVICE GROUP</label>
              <select id="modal-msg-group" class="intune-input" style="width:100%;box-sizing:border-box;">${groupOptions}</select>
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">DELIVERY FREQUENCY</label>
              <select id="modal-msg-frequency" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="ONCE" ${msg?.frequency === 'ONCE' ? 'selected' : ''}>Deliver Once per Device</option>
                <option value="DAILY" ${msg?.frequency === 'DAILY' ? 'selected' : ''}>Daily Reminder</option>
                <option value="EVERY_HEARTBEAT" ${msg?.frequency === 'EVERY_HEARTBEAT' ? 'selected' : ''}>Every Heartbeat Sync</option>
              </select>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">ACTION BUTTON URL / PROTOCOL</label>
              <input id="modal-msg-action-url" class="intune-input" type="text" style="width:100%;box-sizing:border-box;" placeholder="e.g. ms-settings:windowsupdate" value="${esc(msg?.action_url || '')}">
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">ACTION BUTTON LABEL</label>
              <input id="modal-msg-action-label" class="intune-input" type="text" style="width:100%;box-sizing:border-box;" placeholder="e.g. Check for Updates" value="${esc(msg?.action_label || '')}">
            </div>
          </div>

          <div style="display:flex;align-items:center;gap:8px;margin-top:4px;">
            <input type="checkbox" id="modal-msg-enabled" ${!msg || msg.enabled ? 'checked' : ''}>
            <label for="modal-msg-enabled" style="font-size:13px;color:var(--text-primary);cursor:pointer;">Message campaign enabled and delivering</label>
          </div>
        </div>

        <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:20px;">
          <button class="intune-btn" id="btn-cancel-msg-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-save-msg-modal">${isEdit ? 'Save Changes' : 'Create Campaign'}</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';

    // Presets handler
    modal.querySelectorAll('.preset-btn').forEach(b => {
      b.addEventListener('click', () => {
        const p = b.getAttribute('data-preset');
        if (p === 'reboot') {
          modal.querySelector('#modal-msg-title').value = 'Windows Quality Updates Installed — Restart Required';
          modal.querySelector('#modal-msg-body').value = 'Enterprise security patches have been staged on your device. Please reboot at your earliest convenience.';
          modal.querySelector('#modal-msg-surface').value = 'TOAST';
          modal.querySelector('#modal-msg-theme').value = 'UPDATE';
          modal.querySelector('#modal-msg-action-url').value = 'ms-settings:windowsupdate';
          modal.querySelector('#modal-msg-action-label').value = 'Review Updates';
        } else if (p === 'onboarding') {
          modal.querySelector('#modal-msg-title').value = 'Welcome to LocalPilot Enterprise Management';
          modal.querySelector('#modal-msg-body').value = 'Your workstation is enrolled in automated zero-trust health monitoring and security compliance.';
          modal.querySelector('#modal-msg-surface').value = 'TASKBAR';
          modal.querySelector('#modal-msg-theme').value = 'ONBOARDING';
          modal.querySelector('#modal-msg-action-url').value = 'https://github.com/thebubbsy/LocalPilotFleet';
          modal.querySelector('#modal-msg-action-label').value = 'Explore Features';
        } else if (p === 'antivirus') {
          modal.querySelector('#modal-msg-title').value = 'Zero-Trust Security Advisory: Real-Time Protection Required';
          modal.querySelector('#modal-msg-body').value = 'Please ensure Microsoft Defender Antivirus real-time scanning remains active to avoid compliance quarantine.';
          modal.querySelector('#modal-msg-surface').value = 'MODAL';
          modal.querySelector('#modal-msg-theme').value = 'CRITICAL';
          modal.querySelector('#modal-msg-action-url').value = 'windowsdefender:';
          modal.querySelector('#modal-msg-action-label').value = 'Open Security Center';
        }
      });
    });

    modal.querySelector('#btn-close-msg-modal')?.addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#btn-cancel-msg-modal')?.addEventListener('click', () => modal.style.display = 'none');

    modal.querySelector('#btn-save-msg-modal')?.addEventListener('click', async () => {
      const payload = {
        title: modal.querySelector('#modal-msg-title').value,
        messageBody: modal.querySelector('#modal-msg-body').value,
        surface: modal.querySelector('#modal-msg-surface').value,
        theme: modal.querySelector('#modal-msg-theme').value,
        targetGroupId: modal.querySelector('#modal-msg-group').value,
        frequency: modal.querySelector('#modal-msg-frequency').value,
        actionUrl: modal.querySelector('#modal-msg-action-url').value,
        actionLabel: modal.querySelector('#modal-msg-action-label').value,
        enabled: modal.querySelector('#modal-msg-enabled').checked
      };

      try {
        if (isEdit) {
          await window.FleetAPI.updateMessage(msg.id, payload);
          if (typeof showToast === 'function') showToast('Message Updated', 'Organizational message saved.', 'info');
        } else {
          await window.FleetAPI.createMessage(payload);
          if (typeof showToast === 'function') showToast('Message Created', 'New organizational message broadcasting.', 'info');
        }
        modal.style.display = 'none';
        loadData();
      } catch (err) {
        alert(`Failed to save message: ${err.message}`);
      }
    });
  }

  async function showQuickToastModal(targetDeviceId = null) {
    let devices = [];
    try {
      const dData = await window.FleetAPI.getDevices();
      devices = dData.devices || [];
    } catch {}

    let modal = document.getElementById('quick-toast-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'quick-toast-modal';
      modal.className = 'modal-backdrop';
      document.body.appendChild(modal);
    }

    const deviceOptions = devices.map(d => `<option value="${esc(d.id)}" ${d.id === targetDeviceId ? 'selected' : ''}>${esc(d.hostname)} (${esc(d.primary_user || 'No User')})</option>`).join('');

    modal.innerHTML = `
      <div class="modal-card" style="max-width:500px;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:17px;color:var(--text-primary);">⚡ Send Quick Toast Notification</h3>
          <button class="close-btn" id="btn-close-toast-modal" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;">✕</button>
        </div>
        <p style="font-size:13px;color:var(--text-muted);margin:0 0 16px;">
          Deliver an immediate high-priority toast alert to the target workstation user's desktop.
        </p>
        <div style="display:flex;flex-direction:column;gap:12px;">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">TARGET WORKSTATION</label>
            <select id="modal-toast-device" class="intune-input" style="width:100%;box-sizing:border-box;">${deviceOptions}</select>
          </div>
          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">NOTIFICATION TITLE</label>
            <input id="modal-toast-title" class="intune-input" type="text" style="width:100%;box-sizing:border-box;" value="Urgent IT Administration Notice">
          </div>
          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">TOAST MESSAGE</label>
            <textarea id="modal-toast-body" class="intune-input" rows="2" style="width:100%;box-sizing:border-box;font-family:inherit;">Please connect to corporate VPN or sync your workstation settings.</textarea>
          </div>
          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">THEME</label>
            <select id="modal-toast-theme" class="intune-input" style="width:100%;box-sizing:border-box;">
              <option value="WARNING">⚠️ Warning</option>
              <option value="CRITICAL">🚨 Critical</option>
              <option value="UPDATE">🔄 Update</option>
              <option value="INFO">ℹ️ Info</option>
            </select>
          </div>
        </div>
        <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:20px;">
          <button class="intune-btn" id="btn-cancel-toast-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-submit-toast-modal">🚀 Send Toast Now</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';

    modal.querySelector('#btn-close-toast-modal')?.addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#btn-cancel-toast-modal')?.addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#btn-submit-toast-modal')?.addEventListener('click', async () => {
      const devId = modal.querySelector('#modal-toast-device').value;
      const title = modal.querySelector('#modal-toast-title').value;
      const message = modal.querySelector('#modal-toast-body').value;
      const theme = modal.querySelector('#modal-toast-theme').value;

      try {
        await window.FleetAPI.dispatchDeviceToast(devId, { title, message, theme });
        modal.style.display = 'none';
        if (typeof showToast === 'function') showToast('Toast Dispatched', 'Urgent toast queued for immediate node delivery.', 'info');
        loadData();
      } catch (err) {
        alert(`Failed to send toast: ${err.message}`);
      }
    });
  }

  window.MessagesTable = {
    init: loadData,
    refresh: loadData,
    openQuickToastModal: showQuickToastModal
  };
})();
