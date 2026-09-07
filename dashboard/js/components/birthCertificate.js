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

  let _currentDevice = null;

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
    if (hostnameEl) hostnameEl.textContent = 'Loading…';
    if (friendlyEl) friendlyEl.textContent = '';
    body.innerHTML = `
      <div style="padding:24px;">
        ${[...Array(8)].map(() => '<div class="skeleton skeleton-text" style="margin-bottom:14px;height:18px;"></div>').join('')}
      </div>
    `;

    drawer.classList.add('open');
    if (overlay) {
      overlay.classList.add('open');
      overlay.classList.add('active');
    }
    document.body.style.overflow = 'hidden';

    try {
      const device = await window.FleetAPI.getDevice(deviceId);
      _currentDevice = device;

      if (hostnameEl) hostnameEl.textContent = device.hostname || '—';
      if (friendlyEl) {
        friendlyEl.textContent = device.friendly_name && device.friendly_name !== device.hostname
          ? device.friendly_name
          : (device.primary_user ? `👤 Active User: ${device.primary_user}` : 'Windows device | Managed by LocalPilot');
      }

      // Avatar — laptop vs desktop
      if (avatar) avatar.textContent = device.has_battery ? '💻' : '🖥️';

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
    if (overlay) {
      overlay.classList.remove('open');
      overlay.classList.remove('active');
    }
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
      <!-- ── Active User & Console Session ── -->
      <div class="bc-section active-user-blade-card">
        <div class="bc-section-title">👤 Active User &amp; Interactive Session</div>
        <div class="bc-active-user-strip">
          <div class="active-user-avatar">👤</div>
          <div class="active-user-meta">
            <div class="active-user-title">${esc(d.primary_user || 'No logged-in user')}</div>
            <div class="active-user-subtitle">${d.primary_user ? 'Interactive Windows Desktop Session Active' : 'Machine is online with no active desktop session'}</div>
          </div>
          <div class="active-user-pill-wrap">
            <span class="badge ${d.primary_user ? 'badge-online' : 'badge-offline'}">${d.primary_user ? 'Logged In' : 'Console Idle'}</span>
          </div>
        </div>
      </div>

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

      <!-- ── Configuration Profiles & Security Baselines ── -->
      <div class="bc-section" id="bc-profiles-section">
        <div class="bc-section-title">⚙️ Configuration Profiles &amp; Baselines</div>
        <div id="bc-profiles-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading configuration compliance…
        </div>
      </div>

      <!-- ── Windows Update for Business & Patch Status ── -->
      <div class="bc-section" id="bc-updates-section">
        <div class="bc-section-title">🔄 Windows Update for Business &amp; Patches</div>
        <div id="bc-updates-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Windows Update posture…
        </div>
      </div>

      <!-- ── Device Compliance & Zero-Trust Posture ── -->
      <div class="bc-section" id="bc-compliance-section">
        <div class="bc-section-title">🛡️ Device Compliance &amp; Zero-Trust Posture</div>
        <div id="bc-compliance-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading compliance posture…
        </div>
      </div>

      <!-- ── Intune Managed Applications ── -->
      <div class="bc-section" id="bc-apps-section">
        <div class="bc-section-title">📦 Intune Managed Applications &amp; Packaging</div>
        <div id="bc-apps-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading assigned applications…
        </div>
      </div>

      <!-- ── Microsoft Defender Antivirus & Endpoint Security ── -->
      <div class="bc-section" id="bc-security-section">
        <div class="bc-section-title">🛡️ Microsoft Defender &amp; Endpoint Security</div>
        <div id="bc-security-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Defender posture…
        </div>
      </div>

      <!-- ── BitLocker Drive Encryption & Recovery Vault ── -->
      <div class="bc-section" id="bc-bitlocker-section">
        <div class="bc-section-title">🔑 BitLocker Drive Encryption &amp; Recovery Keys</div>
        <div id="bc-bitlocker-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading encryption status…
        </div>
      </div>

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

    // Fetch and populate configuration profiles
    const profListEl = body.querySelector('#bc-profiles-list');
    if (profListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceProfiles(_currentDevice.id).then(res => {
        const profiles = res.profiles || [];
        if (profiles.length === 0) {
          profListEl.innerHTML = '<div style="color:var(--text-muted);">No configuration profiles assigned to this device.</div>';
          return;
        }

        profListEl.innerHTML = `
          <div style="display:flex;flex-direction:column;gap:8px;">
            ${profiles.map(p => {
              const isCompliant = p.compliance_status === 'COMPLIANT';
              const isError = p.compliance_status === 'ERROR';
              const isPending = p.compliance_status === 'PENDING';
              const color = isCompliant ? '#10B981' : (isPending ? '#94a3b8' : (isError ? '#F59E0B' : '#EF4444'));
              const label = isCompliant ? 'Compliant' : (isPending ? 'Pending' : (isError ? 'Error' : 'Non-Compliant'));

              return `
                <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;">
                  <div>
                    <div style="font-weight:600;color:var(--text-bright);font-size:13px;">${esc(p.name)}</div>
                    <div style="font-size:11px;color:var(--text-muted);">${p.settings?.length || 0} settings governed</div>
                  </div>
                  <span class="badge" style="background:${color}22;color:${color};border:1px solid ${color}55;font-weight:600;font-size:11px;">
                    ${label}
                  </span>
                </div>
              `;
            }).join('')}
          </div>
        `;
      }).catch(err => {
        profListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load profiles: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate update ring and patch status
    const updListEl = body.querySelector('#bc-updates-list');
    if (updListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceUpdateStatus(_currentDevice.id).then(status => {
        if (!status || !status.ring_id) {
          updListEl.innerHTML = '<div style="color:var(--text-muted);">No Windows Update telemetry reported yet. Will report on next heartbeat cycle.</div>';
          return;
        }

        const isPending = status.reboot_pending === 1;
        const reasons = status.reboot_pending_reasons || [];
        const hotfixes = status.installed_hotfixes || [];

        updListEl.innerHTML = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px 14px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span style="font-weight:600;color:var(--text-bright);font-size:13px;">${esc(status.ring_name || 'Assigned Update Ring')}</span>
                <span style="font-size:11px;color:var(--text-muted);margin-left:6px;">(${esc(status.servicing_channel || 'GeneralAvailability')})</span>
              </div>
              <span class="badge" style="background:${isPending ? '#EF444422' : '#10B98122'};color:${isPending ? '#EF4444' : '#10B981'};border:1px solid ${isPending ? '#EF444455' : '#10B98155'};font-weight:600;">
                ${isPending ? '⚠️ Reboot Required' : '✓ Up to Date'}
              </span>
            </div>

            ${isPending && reasons.length > 0 ? `
              <div style="font-size:11px;color:#f87171;background:#450a0a44;padding:4px 8px;border-radius:4px;border:1px solid #7f1d1d;">
                <strong>Pending triggers:</strong> ${esc(reasons.join(', '))}
              </div>
            ` : ''}

            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:4px;">
              <div style="font-size:11px;color:var(--text-muted);">
                <strong>Recent hotfixes:</strong>
                ${hotfixes.length > 0 ? hotfixes.slice(0, 3).map(h => `<span class="badge" style="background:#334155;color:#94a3b8;font-size:10px;margin-left:4px;">${esc(h.hotfix_id)}</span>`).join('') : 'None'}
              </div>
              <button class="intune-btn small primary" id="btn-bc-scan-now" style="font-size:11px;padding:2px 8px;">
                ⚡ Scan now
              </button>
            </div>
          </div>
        `;

        updListEl.querySelector('#btn-bc-scan-now')?.addEventListener('click', async () => {
          try {
            await window.FleetAPI.scanDeviceUpdates(_currentDevice.id);
            if (typeof showToast === 'function') showToast('Scan Queued', 'Windows Update scan dispatched to node.', 'info');
          } catch (err) {
            if (typeof showToast === 'function') showToast('Scan Failed', err.message, 'critical');
          }
        });
      }).catch(err => {
        updListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load update status: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate compliance posture
    const compListEl = body.querySelector('#bc-compliance-list');
    if (compListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceCompliance(_currentDevice.id).then(evals => {
        if (!evals || evals.length === 0) {
          compListEl.innerHTML = '<div style="color:var(--text-muted);">No compliance policies assigned or evaluated yet.</div>';
          return;
        }

        compListEl.innerHTML = `
          <div style="display:flex;flex-direction:column;gap:8px;">
            ${evals.map(ev => {
              const isCompliant = ev.compliance_status === 'COMPLIANT';
              const isInGrace = ev.compliance_status === 'IN_GRACE_PERIOD';
              const isQuarantined = ev.device_status === 'quarantined' || ev.action_taken === 'QUARANTINE';
              const color = isCompliant ? '#10B981' : (isInGrace ? '#F59E0B' : '#EF4444');
              const label = isCompliant ? 'Compliant' : (isInGrace ? 'Grace Period' : (isQuarantined ? 'Quarantined' : 'Non-Compliant'));

              let graceText = '';
              if (isInGrace && ev.grace_period_expires_at) {
                const diffMs = new Date(ev.grace_period_expires_at).getTime() - Date.now();
                const diffHours = Math.max(0, Math.round(diffMs / (1000 * 60 * 60)));
                graceText = `<div style="font-size:11px;color:#f59e0b;margin-top:4px;">⏳ Grace period expires in ~${diffHours}h</div>`;
              }

              const failedRules = (ev.rule_evaluations || []).filter(r => !r.passed);

              return `
                <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px 12px;display:flex;flex-direction:column;gap:6px;">
                  <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                      <div style="font-weight:600;color:var(--text-bright);font-size:13px;">${esc(ev.policy_name)}</div>
                      <div style="font-size:11px;color:var(--text-muted);">Action: ${esc(ev.action_taken || 'MARK_NON_COMPLIANT')}</div>
                    </div>
                    <span class="badge" style="background:${color}22;color:${color};border:1px solid ${color}55;font-weight:600;font-size:11px;">
                      ${label}
                    </span>
                  </div>
                  ${graceText}
                  ${failedRules.length > 0 ? `
                    <div style="font-size:11px;color:#f87171;background:#450a0a44;padding:4px 8px;border-radius:4px;border:1px solid #7f1d1d;">
                      <strong>Failed rules:</strong> ${failedRules.map(r => esc(r.rule_name)).join(', ')}
                    </div>
                  ` : ''}
                </div>
              `;
            }).join('')}
            <div style="text-align:right;margin-top:4px;">
              <button class="intune-btn small primary" id="btn-bc-eval-compliance" style="font-size:11px;padding:2px 8px;">
                ⚡ Re-evaluate Compliance
              </button>
            </div>
          </div>
        `;

        compListEl.querySelector('#btn-bc-eval-compliance')?.addEventListener('click', async () => {
          try {
            await window.FleetAPI.evaluateDeviceCompliance(_currentDevice.id);
            if (typeof showToast === 'function') showToast('Compliance Evaluated', 'Zero-trust compliance rules evaluated against latest telemetry.', 'success');
            open(_currentDevice.id);
          } catch (err) {
            if (typeof showToast === 'function') showToast('Evaluation Failed', err.message, 'critical');
          }
        });
      }).catch(err => {
        compListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load compliance status: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate assigned applications
    const appsListEl = body.querySelector('#bc-apps-list');
    if (appsListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceApps(_currentDevice.id).then(apps => {
        if (!apps || apps.length === 0) {
          appsListEl.innerHTML = '<div style="color:var(--text-muted);">No applications assigned to this device.</div>';
          return;
        }

        appsListEl.innerHTML = `
          <div style="display:flex;flex-direction:column;gap:8px;">
            ${apps.map(a => {
              const isInst = a.install_status === 'INSTALLED';
              const isFail = a.install_status === 'FAILED';
              const color = isInst ? '#10b981' : (isFail ? '#ef4444' : '#f59e0b');
              const label = isInst ? 'Installed' : (isFail ? 'Failed' : (a.install_status === 'INSTALLING' ? 'Installing…' : 'Pending'));

              return `
                <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;">
                  <div>
                    <div style="font-weight:600;color:var(--text-bright);font-size:13px;">
                      ${esc(a.name)}
                      <span style="font-size:11px;color:var(--text-muted);font-weight:400;margin-left:4px;">(${esc(a.version || 'Latest')})</span>
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);">${esc(a.assignment_intent)} | ${esc(a.app_type)}</div>
                  </div>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="badge" style="background:${color}22;color:${color};border:1px solid ${color}55;font-weight:600;font-size:11px;">
                      ${label}
                    </span>
                    ${!isInst ? `
                      <button class="intune-btn small primary btn-bc-deploy-app" data-app="${esc(a.id)}" style="font-size:11px;padding:2px 6px;">
                        ⚡ Deploy
                      </button>
                    ` : ''}
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        `;

        appsListEl.querySelectorAll('.btn-bc-deploy-app').forEach(btn => {
          btn.addEventListener('click', async () => {
            const appId = btn.dataset.app;
            try {
              await window.FleetAPI.installDeviceApp(_currentDevice.id, appId);
              if (typeof showToast === 'function') showToast('Deploy Dispatched', 'Application deployment command queued on node.', 'info');
              open(_currentDevice.id);
            } catch (err) {
              if (typeof showToast === 'function') showToast('Deploy Failed', err.message, 'critical');
            }
          });
        });
      }).catch(err => {
        appsListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load applications: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate Defender security status
    const secListEl = body.querySelector('#bc-security-list');
    if (secListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceSecurity(_currentDevice.id).then(sec => {
        if (!sec) {
          secListEl.innerHTML = '<div style="color:var(--text-muted);">No Defender telemetry reported.</div>';
          return;
        }

        const isHealthy = sec.health_status === 'HEALTHY';
        const isCritical = sec.health_status === 'CRITICAL';
        const rtpOn = sec.real_time_protection_enabled === 1;
        const sigAge = sec.signature_age_days ?? 0;

        secListEl.innerHTML = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge ${isHealthy ? 'badge-success' : isCritical ? 'badge-error' : 'badge-warning'}">
                  ${isHealthy ? '✔ Healthy' : isCritical ? '✖ Critical' : '⚠️ Needs Attention'}
                </span>
                <span style="margin-left:8px;font-weight:600;font-size:13px;color:var(--text-bright);">
                  ${rtpOn ? '<span style="color:var(--accent-green);">Real-Time Protection: Active</span>' : '<span style="color:var(--accent-red);">Real-Time Protection: Disabled</span>'}
                </span>
              </div>
              <div style="display:flex;gap:6px;">
                <button class="intune-btn small primary" id="btn-bc-quick-scan" style="font-size:11px;padding:3px 8px;">
                  ⚡ Quick Scan
                </button>
                <button class="intune-btn small" id="btn-bc-update-sigs" style="font-size:11px;padding:3px 8px;">
                  🔄 Update Sigs
                </button>
              </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;">
              <div><span style="color:var(--text-muted);">Signatures:</span> <span class="mono">${esc(sec.signature_version || '—')}</span> (${sigAge}d old)</div>
              <div><span style="color:var(--text-muted);">Engine:</span> <span class="mono">${esc(sec.engine_version || '—')}</span></div>
              <div><span style="color:var(--text-muted);">Ransomware Shield:</span> ${sec.controlled_folder_access_enabled === 1 ? '✔ Enforced' : (sec.controlled_folder_access_enabled === 2 ? 'Audit' : 'Off')}</div>
              <div><span style="color:var(--text-muted);">Last Scan:</span> ${sec.last_quick_scan_at ? new Date(sec.last_quick_scan_at).toLocaleDateString() : 'Never'}</div>
            </div>

            ${(sec.recent_threats || []).length > 0 ? `
              <div style="border-top:1px solid #334155;padding-top:8px;">
                <div style="font-weight:600;color:var(--accent-red);font-size:12px;margin-bottom:4px;">⚠️ Active/Recent Threats:</div>
                ${sec.recent_threats.slice(0, 3).map(t => `
                  <div style="font-size:11px;color:var(--text-muted);display:flex;justify-content:space-between;">
                    <span>${esc(t.threat_name)}</span>
                    <span class="badge ${t.remediation_status === 'ACTIVE' ? 'badge-error' : 'badge-success'}">${esc(t.remediation_status)}</span>
                  </div>
                `).join('')}
              </div>
            ` : ''}
          </div>
        `;

        secListEl.querySelector('#btn-bc-quick-scan')?.addEventListener('click', async () => {
          try {
            await window.FleetAPI.triggerSecurityScan(_currentDevice.id, 'QuickScan');
            if (typeof showToast === 'function') showToast('Defender Scan', `Quick scan initiated on ${_currentDevice.hostname}`, 'info');
          } catch (err) {
            if (typeof showToast === 'function') showToast('Scan Failed', err.message, 'critical');
          }
        });

        secListEl.querySelector('#btn-bc-update-sigs')?.addEventListener('click', async () => {
          try {
            await window.FleetAPI.triggerSignatureUpdate(_currentDevice.id);
            if (typeof showToast === 'function') showToast('Signatures Syncing', `Updating signatures on ${_currentDevice.hostname}`, 'info');
          } catch (err) {
            if (typeof showToast === 'function') showToast('Update Failed', err.message, 'critical');
          }
        });
      }).catch(err => {
        secListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load Defender status: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate BitLocker drive encryption & recovery keys
    const blListEl = body.querySelector('#bc-bitlocker-list');
    if (blListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceBitLocker(_currentDevice.id).then(bl => {
        if (!bl || !bl.volumes || bl.volumes.length === 0) {
          blListEl.innerHTML = '<div style="color:var(--text-muted);">No BitLocker volume data reported for this device.</div>';
          return;
        }

        const isFullyEncrypted = bl.volumes.every(v => v.protection_status === 'ON');
        const hasUnprotected = bl.volumes.some(v => v.protection_status === 'OFF');

        blListEl.innerHTML = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge ${isFullyEncrypted ? 'badge-success' : hasUnprotected ? 'badge-warning' : 'badge-neutral'}">
                  ${isFullyEncrypted ? '🔒 Fully Encrypted' : hasUnprotected ? '⚠️ Unprotected Volumes' : 'ℹ️ Unknown'}
                </span>
                <span style="margin-left:8px;font-weight:600;font-size:13px;color:var(--text-bright);">
                  ${bl.volumes.length} volume(s) registered
                </span>
              </div>
              <div style="display:flex;gap:6px;">
                <button class="intune-btn small primary" id="btn-bc-rotate-keys" style="font-size:11px;padding:3px 8px;">
                  🔄 Rotate Keys
                </button>
                <button class="intune-btn small" id="btn-bc-backup-keys" style="font-size:11px;padding:3px 8px;">
                  ⚡ Backup to Vault
                </button>
              </div>
            </div>

            <table class="bc-sub-table">
              <thead><tr><th>Mount</th><th>Type</th><th>Protection</th><th>Status</th><th>Method</th><th>Protectors</th></tr></thead>
              <tbody>
                ${bl.volumes.map(v => {
                  const protOn = v.protection_status === 'ON';
                  let protectors = [];
                  try { protectors = typeof v.key_protector_types_json === 'string' ? JSON.parse(v.key_protector_types_json) : (v.key_protector_types_json || []); } catch (_) {}
                  return `
                    <tr>
                      <td class="mono" style="font-weight:600;">${esc(v.mount_point)}</td>
                      <td>${esc(v.volume_type || 'OperatingSystem')}</td>
                      <td>
                        <span class="badge ${protOn ? 'badge-success' : 'badge-error'}" style="font-size:10px;">
                          ${protOn ? '🔒 ON' : '🔓 OFF'}
                        </span>
                      </td>
                      <td>${esc(v.volume_status || 'FullyEncrypted')} (${v.encryption_percentage ?? 100}%)</td>
                      <td class="mono" style="font-size:11px;">${esc(v.encryption_method || 'XtsAes128')}</td>
                      <td style="font-size:11px;color:var(--text-muted);">${protectors.map(p => esc(p)).join(', ') || 'None'}</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>

            <div style="border-top:1px solid #334155;padding-top:8px;display:flex;justify-content:space-between;align-items:center;">
              <div style="font-size:11px;color:var(--text-muted);">
                Vault Keys Escrowed: <span style="font-weight:600;color:var(--accent-green);">${(bl.recovery_keys || []).length} key(s)</span>
              </div>
              <button class="intune-btn small" id="btn-bc-view-vault" style="font-size:11px;padding:2px 8px;">
                🔑 View in BitLocker Vault &gt;
              </button>
            </div>
          </div>
        `;

        blListEl.querySelector('#btn-bc-rotate-keys')?.addEventListener('click', async () => {
          try {
            await window.FleetAPI.rotateDeviceBitLockerKeys(_currentDevice.id);
            if (typeof showToast === 'function') showToast('Key Rotation', `Dispatched BitLocker key rotation command to ${_currentDevice.hostname}`, 'info');
          } catch (err) {
            if (typeof showToast === 'function') showToast('Rotation Failed', err.message, 'critical');
          }
        });

        blListEl.querySelector('#btn-bc-backup-keys')?.addEventListener('click', async () => {
          try {
            await window.FleetAPI.backupDeviceBitLockerKeys(_currentDevice.id);
            if (typeof showToast === 'function') showToast('Key Escrow', `Dispatched BitLocker key escrow command to ${_currentDevice.hostname}`, 'info');
          } catch (err) {
            if (typeof showToast === 'function') showToast('Escrow Failed', err.message, 'critical');
          }
        });

        blListEl.querySelector('#btn-bc-view-vault')?.addEventListener('click', () => {
          close();
          if (window.App && typeof window.App.navigate === 'function') {
            window.App.navigate('bitlocker');
          }
        });
      }).catch(err => {
        blListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load BitLocker status: ${esc(err.message)}</div>`;
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

    // Remote Action Ribbon buttons
    const btnRunScript = document.getElementById('btn-blade-terminal');
    btnRunScript?.addEventListener('click', () => {
      if (_currentDevice && window.RemoteTerminal) {
        window.RemoteTerminal.open(_currentDevice.id);
      }
    });

    const btnSync = document.getElementById('btn-blade-sync');
    btnSync?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      try {
        await window.FleetAPI.runScript(_currentDevice.id, 'Get-Date -Format o');
        if (typeof showToast === 'function') showToast('Sync Dispatched', `Check-in requested for ${_currentDevice.hostname}`, 'success');
      } catch (err) {
        if (typeof showToast === 'function') showToast('Sync Failed', err.message, 'critical');
      }
    });

    const btnRestart = document.getElementById('btn-blade-restart');
    btnRestart?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      if (!confirm(`Are you sure you want to remotely reboot ${_currentDevice.hostname}?\nThis will force restart the machine.`)) return;
      try {
        await window.FleetAPI.runScript(_currentDevice.id, 'Restart-Computer -Force');
        if (typeof showToast === 'function') showToast('Reboot Queued', `Restart command queued for ${_currentDevice.hostname}`, 'warning');
      } catch (err) {
        if (typeof showToast === 'function') showToast('Reboot Failed', err.message, 'critical');
      }
    });

    const btnLock = document.getElementById('btn-blade-lock');
    btnLock?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      try {
        await window.FleetAPI.runScript(_currentDevice.id, 'rundll32.exe user32.dll,LockWorkStation');
        if (typeof showToast === 'function') showToast('Remote Lock', `Lock workstation command dispatched to ${_currentDevice.hostname}`, 'info');
      } catch (err) {
        if (typeof showToast === 'function') showToast('Lock Failed', err.message, 'critical');
      }
    });

    const btnScan = document.getElementById('btn-blade-scan');
    btnScan?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      try {
        await window.FleetAPI.triggerSecurityScan(_currentDevice.id, 'QuickScan');
        if (typeof showToast === 'function') showToast('Defender Scan', `Windows Defender quick scan initiated on ${_currentDevice.hostname}`, 'info');
      } catch (err) {
        if (typeof showToast === 'function') showToast('Scan Failed', err.message, 'critical');
      }
    });

    const btnDelete = document.getElementById('btn-delete-device-blade');
    btnDelete?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      if (!confirm(`Permanently decommission and delete ${_currentDevice.hostname} from the fleet?\nThis will erase all historical telemetry and un-assign policies.`)) return;
      try {
        await window.FleetAPI.deleteDevice(_currentDevice.id);
        close();
        if (typeof showToast === 'function') showToast('Device Deleted', `${_currentDevice.hostname} was decommissioned`, 'success');
        if (typeof renderDeviceTable === 'function') renderDeviceTable();
        if (window.OverviewWidgets) window.OverviewWidgets.render();
      } catch (err) {
        if (typeof showToast === 'function') showToast('Delete Failed', err.message, 'critical');
      }
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
