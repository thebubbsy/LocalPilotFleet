/**
 * LocalPilot Fleet — Overview Widgets Component
 * dashboard/js/components/overviewWidgets.js
 *
 * Populates the Overview / Home tab widgets:
 * 1. #overview-devices: Live Windows devices with active logged-in user, CPU/RAM meters, and click-to-inspect.
 * 2. #overview-events: Endpoint security alerts, watchdog triggers, and audit logs.
 */

(function () {
  'use strict';

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatRelativeTime(iso) {
    if (!iso) return '—';
    const diffMs = Date.now() - new Date(iso).getTime();
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'Just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffMin < 1440) return `${Math.floor(diffMin / 60)}h ago`;
    return new Date(iso).toLocaleDateString();
  }

  async function renderOverviewDevices() {
    const container = document.getElementById('overview-devices');
    if (!container) return;

    try {
      const data = await window.FleetAPI.getDevices();
      const devices = data.devices || [];

      if (devices.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-icon">🖥️</div>
            <div class="empty-state-title">No devices enrolled</div>
            <div class="empty-state-msg">Run the agent installer on a target machine to enroll.</div>
          </div>
        `;
        return;
      }

      container.innerHTML = `
        <div class="overview-device-list">
          ${devices.map(d => {
            const isOnline = d.status === 'online';
            const statusClass = d.status === 'online' ? 'badge-online' : (d.status === 'drifted' ? 'badge-drifted' : 'badge-offline');
            const activeUser = d.primary_user || 'No active session';
            const cpuPercent = d.cpu_usage_percent !== undefined && d.cpu_usage_percent !== null ? Number(d.cpu_usage_percent).toFixed(0) : '—';
            const ramGb = d.total_ram_gb ? `${d.total_ram_gb} GB` : (d.total_ram_bytes ? `${(d.total_ram_bytes / 1073741824).toFixed(1)} GB` : '—');

            return `
              <div class="overview-device-card" data-device-id="${esc(d.id)}">
                <div class="card-top-row">
                  <div class="device-ident">
                    <span class="device-type-icon">${d.has_battery ? '💻' : '🖥️'}</span>
                    <div>
                      <div class="device-name">${esc(d.hostname)}</div>
                      <div class="device-os-sub">${esc(d.os_name || 'Windows 11')} (${esc(d.os_build || d.os_version || 'Build —')})</div>
                    </div>
                  </div>
                  <div class="device-status-badge">
                    <span class="badge ${statusClass}">${esc(d.status)}</span>
                  </div>
                </div>

                <div class="card-user-row">
                  <span class="user-pill-label">👤 Logged In:</span>
                  <span class="user-pill-val ${d.primary_user ? 'active-user-highlight' : 'user-muted'}">${esc(activeUser)}</span>
                </div>

                <div class="card-specs-row">
                  <div class="spec-cell">
                    <span class="spec-label">CPU:</span>
                    <span class="spec-val">${esc(d.cpu_model ? d.cpu_model.split('@')[0].trim() : '—')}</span>
                  </div>
                  <div class="spec-cell">
                    <span class="spec-label">RAM:</span>
                    <span class="spec-val">${esc(ramGb)}</span>
                  </div>
                  <div class="spec-cell">
                    <span class="spec-label">IP:</span>
                    <span class="spec-val mono">${esc(d.ip_address || '—')}</span>
                  </div>
                  <div class="spec-cell">
                    <span class="spec-label">Route:</span>
                    <span class="spec-val">${d.connection_route === 'Cloudflare' ? '☁️ Tunnel' : '🏠 LAN'}</span>
                  </div>
                </div>

                <div class="card-action-bar">
                  <button class="intune-btn-sub btn-inspect-card" data-id="${esc(d.id)}">
                    🔍 Inspect Blade
                  </button>
                  <button class="intune-btn-sub btn-terminal-card" data-id="${esc(d.id)}" title="Open Cloud Shell for this machine">
                    &gt;_ Cloud Shell
                  </button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      `;

      // Attach click events
      container.querySelectorAll('.overview-device-card').forEach(card => {
        card.addEventListener('click', (e) => {
          // If clicked inside action buttons, let button handler execute
          if (e.target.closest('button')) return;
          const id = card.getAttribute('data-device-id');
          if (id && window.BirthCertificate) {
            window.BirthCertificate.open(id);
          }
        });
      });

      container.querySelectorAll('.btn-inspect-card').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const id = btn.getAttribute('data-id');
          if (id && window.BirthCertificate) {
            window.BirthCertificate.open(id);
          }
        });
      });

      container.querySelectorAll('.btn-terminal-card').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const id = btn.getAttribute('data-id');
          if (id && window.RemoteTerminal) {
            window.RemoteTerminal.open(id);
          }
        });
      });

    } catch (err) {
      container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠️</div><div class="empty-state-msg">${esc(err.message)}</div></div>`;
    }
  }

  async function renderOverviewEvents() {
    const container = document.getElementById('overview-events');
    if (!container) return;

    try {
      const data = await window.FleetAPI.getEvents({ limit: 6 });
      const events = data.events || data || [];

      if (!Array.isArray(events) || events.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-icon">🛡️</div>
            <div class="empty-state-title">No security alerts</div>
            <div class="empty-state-msg">Windows Defender &amp; Watchdog reported all clear across your fleet.</div>
          </div>
        `;
        return;
      }

      container.innerHTML = `
        <div class="overview-events-list">
          ${events.map(ev => {
            const sev = (ev.severity || 'INFO').toUpperCase();
            const sevClass = sev === 'CRITICAL' ? 'badge-quarantined' : (sev === 'HIGH' ? 'badge-drifted' : 'badge-online');
            return `
              <div class="overview-event-item">
                <div class="event-left">
                  <span class="badge ${sevClass}">${esc(sev)}</span>
                  <div class="event-summary-wrap">
                    <div class="event-summary">${esc(ev.summary || ev.description || ev.event_type)}</div>
                    <div class="event-meta">${esc(ev.hostname || 'Device')} • ${formatRelativeTime(ev.created_at)}</div>
                  </div>
                </div>
                ${ev.acknowledged ? '<span class="event-ack-tag">✔ Ack</span>' : ''}
              </div>
            `;
          }).join('')}
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠️</div><div class="empty-state-msg">${esc(err.message)}</div></div>`;
    }
  }

  function renderAll() {
    renderOverviewDevices();
    renderOverviewEvents();
  }

  window.OverviewWidgets = {
    render: renderAll,
    renderDevices: renderOverviewDevices,
    renderEvents: renderOverviewEvents
  };
})();
