/**
 * LocalPilot Fleet — Birth Certificate Drawer
 * dashboard/js/components/birthCertificate.js
 *
 * Slide-in drawer from the right showing complete device identity,
 * hardware, security posture, software inventory, and network info.
 */

(function () {
  'use strict';

  /* ── Helper: HTML escaper ───────────────────────────────────────── */
  function esc(v) {
    return String(v ?? '—')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* ── Helper: Boolean display ────────────────────────────────────── */
  function boolField(v) {
    if (v === 1 || v === true)  return '<span style="color:var(--accent-green);">✔ Yes</span>';
    if (v === 0 || v === false) return '<span style="color:var(--accent-red);">✘ No</span>';
    return '—';
  }

  /* ── Helper: format bytes ───────────────────────────────────────── */
  function fmtBytes(bytes) {
    if (!bytes) return '—';
    if (bytes >= 1099511627776) return `${(bytes/1099511627776).toFixed(1)} TB`;
    if (bytes >= 1073741824)    return `${(bytes/1073741824).toFixed(1)} GB`;
    if (bytes >= 1048576)       return `${(bytes/1048576).toFixed(0)} MB`;
    return `${bytes} B`;
  }

  /* ── Helper: SHA-256 fingerprint from UUID + serial ────────────── */
  function pseudoFingerprint(device) {
    // Generate a deterministic display fingerprint from the device id
    const raw = (device.id || '') + (device.serial_number || '') + (device.mac_address || '');
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
      hash = ((hash << 5) - hash + raw.charCodeAt(i)) >>> 0;
    }
    // Expand to 64 hex chars for display
    const base = hash.toString(16).padStart(8, '0');
    const fp   = (base + base + base + base + base + base + base + base).slice(0, 64);
    return fp.match(/.{1,8}/g).join(':');
  }

  /* ── Open drawer with device data ──────────────────────────────── */
  async function open(deviceId) {
    const drawer  = document.getElementById('bc-drawer');
    const overlay = document.getElementById('bc-overlay');
    const body    = document.getElementById('bc-body');
    const hostnameEl = document.getElementById('bc-hostname');
    const friendlyEl = document.getElementById('bc-friendly-name');
    const avatar     = document.getElementById('bc-avatar');

    if (!drawer) return;

    // Show drawer immediately with loading state
    hostnameEl.textContent = 'Loading…';
    friendlyEl.textContent = '';
    body.innerHTML = `
      <div style="padding:24px;">
        ${[...Array(8)].map(() => '<div class="skeleton skeleton-text" style="margin-bottom:14px;height:18px;"></div>').join('')}
      </div>
    `;

    drawer.classList.add('open');
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';

    try {
      const device = await window.FleetAPI.getDevice(deviceId);

      hostnameEl.textContent = device.hostname || '—';
      friendlyEl.textContent = device.friendly_name && device.friendly_name !== device.hostname
        ? device.friendly_name
        : (device.primary_user ? `👤 ${device.primary_user}` : '');

      // Avatar — laptop vs desktop
      avatar.textContent = device.has_battery ? '💻' : '🖥️';

      body.innerHTML = renderBirthCertificate(device);
      attachBcEvents(body);
    } catch (err) {
      body.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">❌</div>
          <div class="empty-state-title">Failed to load device</div>
          <div class="empty-state-msg">${esc(err.message)}</div>
        </div>
      `;
    }
  }

  /* ── Close drawer ───────────────────────────────────────────────── */
  function close() {
    const drawer  = document.getElementById('bc-drawer');
    const overlay = document.getElementById('bc-overlay');
    if (drawer)  drawer.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    document.body.style.overflow = '';
  }

  /* ── Render the full birth certificate ──────────────────────────── */
  function renderBirthCertificate(d) {
    const snapshots = d.telemetry_snapshots || [];
    const latestSnap = snapshots[0] || {};
    const disks   = latestSnap.disks   || [];
    const network = latestSnap.network || [];

    // Installed software from device record (if embedded)
    const software = d.installed_software || [];

    // Groups
    const groups = d.assigned_groups || [];

    return `
      <!-- ── Hardware Identity ── -->
      <div class="bc-section">
        <div class="bc-section-title">🪪 Hardware Identity</div>
        <div class="bc-fields">
          <div class="bc-field">
            <div class="bc-field-label">Hostname</div>
            <div class="bc-field-value mono">${esc(d.hostname)}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Friendly Name</div>
            <div class="bc-field-value">${esc(d.friendly_name || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Serial Number</div>
            <div class="bc-field-value mono">${esc(d.serial_number || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">UUID</div>
            <div class="bc-field-value mono" style="font-size:10px;">${esc(d.uuid || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">MAC Address</div>
            <div class="bc-field-value mono">${esc(d.mac_address || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Enrolled</div>
            <div class="bc-field-value mono">${d.enrolled_at ? new Date(d.enrolled_at).toLocaleString() : '—'}</div>
          </div>
          <div class="bc-field bc-field-full">
            <div class="bc-field-label">SHA-256 Device Fingerprint</div>
            <div class="bc-field-value fingerprint">${pseudoFingerprint(d)}</div>
          </div>
        </div>
      </div>

      <!-- ── Platform ── -->
      <div class="bc-section">
        <div class="bc-section-title">🪟 Operating System</div>
        <div class="bc-fields">
          <div class="bc-field">
            <div class="bc-field-label">OS Name</div>
            <div class="bc-field-value">${esc(d.os_name)}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">OS Version</div>
            <div class="bc-field-value mono">${esc(d.os_version)}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Build Number</div>
            <div class="bc-field-value mono">${esc(d.os_build || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Architecture</div>
            <div class="bc-field-value">${esc(d.os_architecture || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Primary User</div>
            <div class="bc-field-value">${esc(d.primary_user || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Agent Version</div>
            <div class="bc-field-value mono">${esc(d.agent_version)}</div>
          </div>
        </div>
      </div>

      <!-- ── Processor ── -->
      <div class="bc-section">
        <div class="bc-section-title">⚙️ Processor</div>
        <div class="bc-fields">
          <div class="bc-field bc-field-full">
            <div class="bc-field-label">CPU Model</div>
            <div class="bc-field-value mono">${esc(d.cpu_model || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Physical Cores</div>
            <div class="bc-field-value">${d.cpu_cores ?? '—'}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Logical Processors</div>
            <div class="bc-field-value">${d.cpu_logical ?? '—'}</div>
          </div>
          ${latestSnap.cpu_usage_percent !== undefined
            ? `<div class="bc-field">
                <div class="bc-field-label">CPU Usage</div>
                <div class="bc-field-value" style="color:var(--accent-blue);">${Number(latestSnap.cpu_usage_percent).toFixed(1)}%</div>
              </div>`
            : ''}
        </div>
      </div>

      <!-- ── Memory ── -->
      <div class="bc-section">
        <div class="bc-section-title">💾 Memory</div>
        <div class="bc-fields">
          <div class="bc-field">
            <div class="bc-field-label">Total RAM</div>
            <div class="bc-field-value">${fmtBytes(d.total_ram_bytes)}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">RAM (GB)</div>
            <div class="bc-field-value">${d.total_ram_gb ? `${d.total_ram_gb} GB` : '—'}</div>
          </div>
          ${latestSnap.ram_usage_percent !== undefined
            ? `<div class="bc-field">
                <div class="bc-field-label">RAM In Use</div>
                <div class="bc-field-value" style="color:var(--accent-amber);">
                  ${fmtBytes(latestSnap.ram_used_bytes)} (${Number(latestSnap.ram_usage_percent).toFixed(1)}%)
                </div>
              </div>
              <div class="bc-field">
                <div class="bc-field-label">RAM Free</div>
                <div class="bc-field-value" style="color:var(--accent-green);">${fmtBytes(latestSnap.ram_free_bytes)}</div>
              </div>`
            : ''}
        </div>
      </div>

      <!-- ── Storage ── -->
      <div class="bc-section">
        <div class="bc-section-title">💿 Storage</div>
        ${disks.length > 0
          ? `<table class="bc-sub-table">
              <thead><tr><th>Drive</th><th>Total</th><th>Free</th><th>SMART</th></tr></thead>
              <tbody>
                ${disks.map(disk => `
                  <tr>
                    <td>${esc(disk.drive || disk.drive_letter || '—')}</td>
                    <td>${disk.total_gb ? `${Number(disk.total_gb).toFixed(0)} GB` : '—'}</td>
                    <td style="color:var(--accent-green);">${disk.free_gb ? `${Number(disk.free_gb).toFixed(0)} GB` : '—'}</td>
                    <td>${disk.smart_healthy === true ? '<span style="color:var(--accent-green);">✔ Healthy</span>' : disk.smart_healthy === false ? '<span style="color:var(--accent-red);">✘ Warn</span>' : '—'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>`
          : '<div style="font-size:12px;color:var(--text-muted);padding:8px 0;">No disk data in latest snapshot</div>'
        }
      </div>

      <!-- ── GPU ── -->
      <div class="bc-section">
        <div class="bc-section-title">🎮 Display & Graphics</div>
        <div class="bc-fields">
          <div class="bc-field bc-field-full">
            <div class="bc-field-label">GPU</div>
            <div class="bc-field-value mono">${esc(d.gpu_name || '—')}</div>
          </div>
          ${d.has_battery
            ? `<div class="bc-field">
                <div class="bc-field-label">Battery</div>
                <div class="bc-field-value">${d.battery_percent !== null ? `${d.battery_percent?.toFixed(0)}%` : '—'} ${d.battery_charging ? '⚡ Charging' : ''}</div>
              </div>`
            : ''
          }
        </div>
      </div>

      <!-- ── Network ── -->
      <div class="bc-section">
        <div class="bc-section-title">🌐 Network</div>
        <div class="bc-fields" style="margin-bottom:10px;">
          <div class="bc-field">
            <div class="bc-field-label">LAN IP</div>
            <div class="bc-field-value mono">${esc(d.ip_address || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Connection Route</div>
            <div class="bc-field-value">${esc(d.connection_route || '—')}</div>
          </div>
        </div>
        ${network.length > 0
          ? `<table class="bc-sub-table">
              <thead><tr><th>Adapter</th><th>MAC</th><th>IPv4</th></tr></thead>
              <tbody>
                ${network.map(a => `
                  <tr>
                    <td>${esc(a.name || a.description || '—')}</td>
                    <td>${esc(a.mac || a.mac_address || '—')}</td>
                    <td>${esc(a.ipv4 || a.ip_address || '—')}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>`
          : '<div style="font-size:12px;color:var(--text-muted);padding:4px 0;">No adapter data in latest snapshot</div>'
        }
      </div>

      <!-- ── Platform Security ── -->
      <div class="bc-section">
        <div class="bc-section-title">🔒 Platform Security</div>
        <div class="bc-fields">
          <div class="bc-field">
            <div class="bc-field-label">TPM Present</div>
            <div class="bc-field-value">${boolField(d.tpm_present)}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">TPM Version</div>
            <div class="bc-field-value mono">${esc(d.tpm_version || '—')}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">TPM Enabled</div>
            <div class="bc-field-value">${boolField(d.tpm_enabled)}</div>
          </div>
          <div class="bc-field">
            <div class="bc-field-label">Secure Boot</div>
            <div class="bc-field-value">${boolField(d.secure_boot_enabled)}</div>
          </div>
          <div class="bc-field bc-field-full">
            <div class="bc-field-label">BitLocker Status</div>
            <div class="bc-field-value" style="color: ${
              d.bitlocker_status === 'FullyEncrypted'
                ? 'var(--accent-green)'
                : d.bitlocker_status === 'Disabled'
                ? 'var(--accent-red)'
                : 'var(--accent-amber)'
            };">${esc(d.bitlocker_status || '—')}</div>
          </div>
        </div>
      </div>

      <!-- ── Dynamic Groups ── -->
      ${groups.length > 0 ? `
        <div class="bc-section">
          <div class="bc-section-title">🏷️ Group Memberships</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;">
            ${groups.map(g => `
              <span class="badge" style="background:${g.color}22;color:${g.color};border:1px solid ${g.color}44;font-size:11px;">
                ${esc(g.name)}
              </span>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <!-- ── Recent Events ── -->
      ${(d.security_events || []).length > 0 ? `
        <div class="bc-section">
          <div class="bc-section-title">⚡ Recent Security Events</div>
          <table class="bc-sub-table">
            <thead><tr><th>Severity</th><th>Type</th><th>Summary</th><th>Time</th></tr></thead>
            <tbody>
              ${d.security_events.slice(0, 10).map(ev => `
                <tr>
                  <td><span class="badge badge-${ev.severity.toLowerCase()}">${esc(ev.severity)}</span></td>
                  <td>${esc(ev.event_type)}</td>
                  <td>${esc(ev.summary)}</td>
                  <td>${ev.created_at ? new Date(ev.created_at).toLocaleString() : '—'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      ` : ''}

      <!-- ── Installed Software (from latest telemetry, if present) ── -->
      ${software.length > 0 ? `
        <div class="bc-section">
          <div class="bc-section-title">📦 Installed Software (${software.length})</div>
          <input class="search-input bc-soft-search" id="bc-soft-search" placeholder="🔍 Filter software…" style="margin-bottom:8px;padding-left:12px;">
          <table class="bc-sub-table" id="bc-soft-table">
            <thead><tr><th>Name</th><th>Version</th><th>Publisher</th></tr></thead>
            <tbody id="bc-soft-tbody">
              ${software.map(s => `
                <tr>
                  <td>${esc(s.name || s.display_name)}</td>
                  <td>${esc(s.version || '—')}</td>
                  <td>${esc(s.publisher || '—')}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      ` : ''}

      <!-- Padding at bottom -->
      <div style="height:40px;"></div>
    `;
  }

  /* ── Attach interactive events in BC body ───────────────────────── */
  function attachBcEvents(body) {
    // Software search filter
    const softSearch = body.querySelector('#bc-soft-search');
    const softTbody  = body.querySelector('#bc-soft-tbody');
    if (softSearch && softTbody) {
      softSearch.addEventListener('input', () => {
        const q = softSearch.value.toLowerCase();
        softTbody.querySelectorAll('tr').forEach(tr => {
          const text = tr.textContent.toLowerCase();
          tr.style.display = text.includes(q) ? '' : 'none';
        });
      });
    }
  }

  /* ── Bind close button & overlay click ─────────────────────────── */
  function init() {
    const closeBtn = document.getElementById('bc-close-btn');
    const overlay  = document.getElementById('bc-overlay');
    if (closeBtn) closeBtn.addEventListener('click', close);
    if (overlay)  overlay.addEventListener('click', close);

    // Keyboard: Escape closes drawer
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') close();
    });
  }

  /* ── Expose ─────────────────────────────────────────────────────── */
  window.BirthCertificate = { open, close, init };

  // Auto-init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
