/**
 * LocalPilot Fleet — Security Audit & Activity Feed (Intune Style)
 * dashboard/js/components/activityFeed.js
 */

async function renderActivityFeed() {
  const container = document.getElementById('events-container');
  if (!container) return;

  container.innerHTML = `
    <div class="intune-blade-header">
      <div class="intune-breadcrumb">Home &gt; Endpoint security &gt; Monitoring &gt; Security events</div>
      <div class="intune-title-row">
        <div class="intune-title-icon">⚡</div>
        <div>
          <h1 class="intune-blade-title">Endpoint security | Security events</h1>
          <p class="intune-blade-subtitle">Real-time audit log of Windows Security Event Log triggers (Event 4720, 4726, 4728/4732) and unauthorized software drift</p>
        </div>
      </div>
    </div>

    <!-- Command Bar -->
    <div class="intune-command-bar">
      <button class="intune-cmd-btn" id="btn-refresh-events">
        <span class="cmd-icon">🔄</span> Refresh
      </button>
      <div class="intune-cmd-separator"></div>
      <div class="intune-filter-group">
        <label class="filter-label">Severity:</label>
        <select id="event-severity-filter" class="intune-select-sm">
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      <div class="intune-filter-group">
        <label class="filter-label">Status:</label>
        <select id="event-ack-filter" class="intune-select-sm">
          <option value="">All</option>
          <option value="false" selected>Unacknowledged (Active)</option>
          <option value="true">Acknowledged</option>
        </select>
      </div>
      <div class="intune-cmd-separator"></div>
      <div class="intune-search-box">
        <span class="search-icon">🔍</span>
        <input type="text" id="event-search-input" placeholder="Search event description or device..." />
      </div>
    </div>

    <!-- Events Table -->
    <div class="intune-grid-container">
      <table class="intune-table" id="events-table">
        <thead>
          <tr>
            <th style="width: 170px;">Timestamp</th>
            <th>Device</th>
            <th>Event type</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Status</th>
            <th style="text-align: right; width: 100px;">Action</th>
          </tr>
        </thead>
        <tbody id="events-table-body">
          <tr><td colspan="7" class="intune-loading">Loading security audit feed...</td></tr>
        </tbody>
      </table>
    </div>
  `;

  // Bind Events
  document.getElementById('btn-refresh-events')?.addEventListener('click', loadEventsData);
  document.getElementById('event-severity-filter')?.addEventListener('change', loadEventsData);
  document.getElementById('event-ack-filter')?.addEventListener('change', loadEventsData);

  loadEventsData();
}

async function loadEventsData() {
  const tbody = document.getElementById('events-table-body');
  if (!tbody) return;

  const severity = document.getElementById('event-severity-filter')?.value || '';
  const ack = document.getElementById('event-ack-filter')?.value || '';

  const params = {};
  if (severity) params.severity = severity;
  if (ack) params.acknowledged = ack;

  try {
    const res = await apiFetch(`/api/v1/fleet/events?${new URLSearchParams(params).toString()}`);
    const events = Array.isArray(res) ? res : (res?.events || []);
    if (!events || events.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="intune-empty">No security events found matching the selected filter. Fleet is secure.</td></tr>`;
      return;
    }

    tbody.innerHTML = events.map(ev => {
      let sevBadge = '<span class="intune-badge gray">Low</span>';
      if (ev.severity === 'critical') sevBadge = '<span class="intune-badge red pulse">🚨 CRITICAL</span>';
      else if (ev.severity === 'high') sevBadge = '<span class="intune-badge orange">⚠️ HIGH</span>';
      else if (ev.severity === 'medium') sevBadge = '<span class="intune-badge amber">⚡ MEDIUM</span>';

      const isAck = ev.acknowledged === 1 || ev.acknowledged === true;
      const statusBadge = isAck
        ? '<span class="intune-badge neutral">Acknowledged</span>'
        : '<span class="intune-badge red">Active Alert</span>';

      const ackButton = isAck
        ? '<span class="text-secondary" style="font-size:12px;">Resolved</span>'
        : `<button class="intune-btn secondary small" onclick="ackEventPrompt('${ev.id}')">Acknowledge</button>`;

      return `
        <tr class="intune-row ${isAck ? 'row-acknowledged' : ''}">
          <td class="text-secondary code-font" style="font-size:12px;">${formatDate(ev.created_at)}</td>
          <td>
            <span class="device-link">${ev.hostname || ev.device_id || 'Fleet Node'}</span>
          </td>
          <td><strong>${formatEventType(ev.event_type)}</strong></td>
          <td>${sevBadge}</td>
          <td>${escapeHtml(ev.description || '—')}</td>
          <td>${statusBadge}</td>
          <td style="text-align: right;">${ackButton}</td>
        </tr>
      `;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="intune-error">Error loading events: ${e.message}</td></tr>`;
  }
}

async function ackEventPrompt(id) {
  try {
    await apiFetch(`/api/v1/fleet/events/${id}/ack`, { method: 'POST' });
    loadEventsData();
    showToast('Alert Acknowledged', 'Security event marked as resolved.', 'info');
  } catch (e) {
    alert('Failed to acknowledge event: ' + e.message);
  }
}

function formatEventType(type) {
  switch (type) {
    case 'user_created': return '👤 User Account Created (4720)';
    case 'user_deleted': return '❌ User Account Deleted (4726)';
    case 'privilege_escalation': return '👑 Admin Rights Granted (4728)';
    case 'software_installed': return '📦 Application Installed';
    case 'drift_detected': return '⚠️ Security Policy Drift';
    default: return type || 'Security Event';
  }
}

function formatDate(isoStr) {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  } catch {
    return isoStr;
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
