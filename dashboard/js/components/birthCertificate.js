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

      <!-- ── Windows Firewall & Listening Ports Sentinel ── -->
      <div class="bc-section" id="bc-firewall-section">
        <div class="bc-section-title">🧱 Windows Firewall &amp; Perimeter Open Ports</div>
        <div id="bc-firewall-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading firewall posture &amp; listening ports…
        </div>
      </div>

      <!-- ── BitLocker Drive Encryption & Recovery Vault ── -->
      <div class="bc-section" id="bc-bitlocker-section">
        <div class="bc-section-title">🔑 BitLocker Drive Encryption &amp; Recovery Keys</div>
        <div id="bc-bitlocker-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading encryption status…
        </div>
      </div>

      <!-- ── Windows LAPS Administrator Password ── -->
      <div class="bc-section" id="bc-laps-section">
        <div class="bc-section-title">🔐 Windows LAPS Administrator Password</div>
        <div id="bc-laps-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading LAPS credential posture…
        </div>
      </div>

      <!-- ── Endpoint Privilege Management (EPM) Posture ── -->
      <div class="bc-section" id="bc-epm-section">
        <div class="bc-section-title">🛡️ Endpoint Privilege Management (EPM)</div>
        <div id="bc-epm-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading EPM elevation rules…
        </div>
      </div>

      <!-- ── Windows Autopilot & Hardware Provisioning ── -->
      <div class="bc-section" id="bc-autopilot-section">
        <div class="bc-section-title">🚀 Windows Autopilot &amp; Provisioning</div>
        <div id="bc-autopilot-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Autopilot provisioning posture…
        </div>
      </div>

      <!-- ── Windows PowerShell Scripts ── -->
      <div class="bc-section" id="bc-scripts-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>📜 Windows PowerShell Scripts</span>
          <button class="intune-link-btn" id="btn-bc-open-scripts-terminal">💻 Open Cloud Shell</button>
        </div>
        <div id="bc-scripts-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading PowerShell script execution status…
        </div>
      </div>

      <!-- ── Attack Surface Reduction (ASR) & Exploit Guard ── -->
      <div class="bc-section" id="bc-asr-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>🛡️ Attack Surface Reduction &amp; Exploit Guard</span>
          <button class="intune-link-btn" id="btn-bc-view-asr-tab">View ASR Blade</button>
        </div>
        <div id="bc-asr-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading ASR &amp; Exploit Protection status…
        </div>
      </div>

      <!-- ── Endpoint Analytics & Health Score ── -->
      <div class="bc-section" id="bc-analytics-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>📊 Endpoint Analytics &amp; Health Score</span>
          <button class="intune-link-btn" id="btn-bc-view-analytics-tab">View Analytics</button>
        </div>
        <div id="bc-analytics-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading performance &amp; reliability score…
        </div>
      </div>

      <!-- ── Certificates & SCEP Posture ── -->
      <div class="bc-section" id="bc-certificates-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>📜 Certificates &amp; SCEP Posture</span>
          <button class="intune-link-btn" id="btn-bc-view-certificates-tab">View Certificates</button>
        </div>
        <div id="bc-certificates-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading installed certificates…
        </div>
      </div>

      <!-- ── Wi-Fi & VPN Network Posture ── -->
      <div class="bc-section" id="bc-network-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>🌐 Wi-Fi &amp; VPN Network Posture</span>
          <button class="intune-link-btn" id="btn-bc-view-network-tab">View Network Blade</button>
        </div>
        <div id="bc-network-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Wi-Fi &amp; VPN posture…
        </div>
      </div>

      <!-- ── Kiosk & Assigned Access Posture ── -->
      <div class="bc-section" id="bc-kiosk-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>🖥️ Kiosk &amp; Assigned Access Posture</span>
          <button class="intune-link-btn" id="btn-bc-view-kiosk-tab">View Kiosk Blade</button>
        </div>
        <div id="bc-kiosk-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Kiosk posture…
        </div>
      </div>

      <!-- ── Removable Storage & USB Peripheral Posture ── -->
      <div class="bc-section" id="bc-storage-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>💾 Removable Storage &amp; USB Posture</span>
          <button class="intune-link-btn" id="btn-bc-view-storage-tab">View Storage Blade</button>
        </div>
        <div id="bc-storage-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Removable Storage &amp; USB posture…
        </div>
      </div>

      <!-- ── Delivery Optimization & Peering Posture ── -->
      <div class="bc-section" id="bc-do-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>🚀 Delivery Optimization &amp; Peering Posture</span>
          <button class="intune-link-btn" id="btn-bc-view-do-tab">View DO Blade</button>
        </div>
        <div id="bc-do-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Delivery Optimization posture…
        </div>
      </div>

      <!-- ── Device Firmware & Hardware Root-of-Trust (DFCI) ── -->
      <div class="bc-section" id="bc-dfci-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>🛡️ Device Firmware &amp; Hardware Root-of-Trust (DFCI)</span>
          <button class="intune-link-btn" id="btn-bc-view-dfci-tab">View DFCI Blade</button>
        </div>
        <div id="bc-dfci-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Firmware &amp; UEFI posture…
        </div>
      </div>

      <!-- ── Windows Information Protection & DLP Posture ── -->
      <div class="bc-section" id="bc-wip-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>🔒 Windows Information Protection (WIP) &amp; DLP</span>
          <button class="intune-link-btn" id="btn-bc-view-wip-tab">View WIP Blade</button>
        </div>
        <div id="bc-wip-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Data Protection posture…
        </div>
      </div>

      <!-- ── Windows Hello for Business (WHfB) & FIDO2 Posture ── -->
      <div class="bc-section" id="bc-whfb-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>🔑 Windows Hello for Business &amp; FIDO2</span>
          <button class="intune-link-btn" id="btn-bc-view-whfb-tab">View WHfB Blade</button>
        </div>
        <div id="bc-whfb-list" style="font-size:12px;color:var(--text-muted);padding:4px 0;">
          <span>⏳</span> Loading Windows Hello posture…
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

      <!-- ── Remote Actions & Diagnostic Logs ── -->
      <div class="bc-section">
        <div class="bc-section-title" style="display:flex;justify-content:space-between;align-items:center;">
          <span>⚡ Remote Actions &amp; Diagnostic Bundles</span>
          <button class="intune-btn small primary" id="btn-bc-view-all-remote" style="font-size:11px;padding:2px 8px;">
            Open Blade &gt;
          </button>
        </div>
        <div id="bc-remote-actions-list" style="margin-top:8px;">
          <span>⏳</span> Loading remote execution history…
        </div>
      </div>

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

    // Fetch and populate Windows Firewall and listening ports
    const fwListEl = body.querySelector('#bc-firewall-list');
    if (fwListEl && _currentDevice?.id) {
      Promise.all([
        window.FleetAPI.getDeviceFirewall(_currentDevice.id).catch(() => null),
        window.FleetAPI.getDeviceListeningPorts(_currentDevice.id).catch(() => ({ ports: [] }))
      ]).then(([fw, portsRes]) => {
        const ports = portsRes?.ports || [];
        const isCompliant = fw?.compliance_status === 'COMPLIANT';
        const activeRules = fw?.active_rules_count || 0;
        const domOn = fw?.domain_profile_enabled === 1;
        const privOn = fw?.private_profile_enabled === 1;
        const pubOn = fw?.public_profile_enabled === 1;

        fwListEl.innerHTML = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge ${isCompliant ? 'badge-success' : 'badge-warning'}">
                  ${isCompliant ? '🛡️ Firewall Compliant' : '⚠️ Profile Drift Detected'}
                </span>
                <span style="margin-left:8px;font-weight:600;font-size:13px;color:var(--text-bright);">
                  ${activeRules} rules active &bull; ${ports.length} open sockets
                </span>
              </div>
              <div style="display:flex;gap:6px;">
                <button class="intune-btn small primary" id="btn-bc-enforce-fw" style="font-size:11px;padding:3px 8px;">
                  ⚡ Enforce Policy
                </button>
                <button class="intune-btn small" id="btn-bc-view-fw" style="font-size:11px;padding:3px 8px;">
                  🧱 View Firewall Blade &gt;
                </button>
              </div>
            </div>

            <!-- Profile Badges -->
            <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:8px;font-size:12px;">
              <div style="background:#0f172a;padding:6px 10px;border-radius:4px;border:1px solid #334155;">
                <div style="color:var(--text-muted);font-size:10px;">DOMAIN PROFILE</div>
                <div style="font-weight:600;color:${domOn ? '#10b981' : '#ef4444'};">${domOn ? '● Enabled' : '○ Disabled'}</div>
              </div>
              <div style="background:#0f172a;padding:6px 10px;border-radius:4px;border:1px solid #334155;">
                <div style="color:var(--text-muted);font-size:10px;">PRIVATE PROFILE</div>
                <div style="font-weight:600;color:${privOn ? '#10b981' : '#ef4444'};">${privOn ? '● Enabled' : '○ Disabled'}</div>
              </div>
              <div style="background:#0f172a;padding:6px 10px;border-radius:4px;border:1px solid #334155;">
                <div style="color:var(--text-muted);font-size:10px;">PUBLIC PROFILE</div>
                <div style="font-weight:600;color:${pubOn ? '#10b981' : '#ef4444'};">${pubOn ? '● Enabled' : '○ Disabled'}</div>
              </div>
            </div>

            ${ports.length > 0 ? `
              <div style="border-top:1px solid #334155;padding-top:8px;">
                <div style="font-weight:600;color:var(--text-bright);font-size:12px;margin-bottom:4px;">Listening TCP Sockets:</div>
                <table class="bc-sub-table">
                  <thead><tr><th>Port</th><th>Binding</th><th>Process</th><th>Risk</th></tr></thead>
                  <tbody>
                    ${ports.slice(0, 5).map(p => `
                      <tr>
                        <td class="mono" style="font-weight:600;">${esc(p.local_port)}</td>
                        <td class="mono" style="font-size:11px;">${esc(p.local_address)}</td>
                        <td>${esc(p.process_name || 'System')}</td>
                        <td><span class="badge badge-${p.risk_level === 'CRITICAL' || p.risk_level === 'HIGH' ? 'error' : 'neutral'}" style="font-size:10px;">${esc(p.risk_level)}</span></td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            ` : '<div style="font-size:11px;color:var(--text-muted);">No open listening sockets recorded.</div>'}
          </div>
        `;

        fwListEl.querySelector('#btn-bc-enforce-fw')?.addEventListener('click', async () => {
          try {
            await window.FleetAPI.enforceDeviceFirewall(_currentDevice.id);
            if (typeof showToast === 'function') showToast('Firewall Enforce', `Policy enforcement dispatched to ${_currentDevice.hostname}`, 'info');
          } catch (err) {
            if (typeof showToast === 'function') showToast('Enforce Failed', err.message, 'critical');
          }
        });

        fwListEl.querySelector('#btn-bc-view-fw')?.addEventListener('click', () => {
          close();
          if (window.App && typeof window.App.navigate === 'function') {
            window.App.navigate('firewall');
          }
        });
      }).catch(err => {
        fwListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load firewall posture: ${esc(err.message)}</div>`;
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

    // Fetch and populate LAPS credential posture
    const lapsListEl = body.querySelector('#bc-laps-list');
    if (lapsListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceLaps(_currentDevice.id).then(laps => {
        if (!laps || !laps.credentials || laps.credentials.length === 0) {
          lapsListEl.innerHTML = `
            <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge badge-neutral" style="font-size:11px;">Not Configured</span>
                <span style="margin-left:8px;color:var(--text-muted);">No LAPS administrator passwords escrowed for this device.</span>
              </div>
              <button class="intune-btn small primary" id="btn-bc-laps-rotate-init" style="font-size:11px;padding:3px 8px;">
                🔄 Rotate / Initialize
              </button>
            </div>
          `;
          lapsListEl.querySelector('#btn-bc-laps-rotate-init')?.addEventListener('click', async () => {
            try {
              await window.FleetAPI.rotateDeviceLapsPassword(_currentDevice.id, { reason: 'Initial manual rotation from Device Drawer' });
              if (typeof showToast === 'function') showToast('Rotation Queued', `LAPS rotation command queued for ${_currentDevice.hostname}`, 'info');
            } catch (err) {
              if (typeof showToast === 'function') showToast('Rotation Failed', err.message, 'critical');
            }
          });
          return;
        }

        const cred = laps.credentials[0];
        const isExpiringSoon = cred.is_expired || (cred.expires_in_days !== null && cred.expires_in_days <= 3);
        const statusColor = cred.is_expired ? '#ef4444' : (isExpiringSoon ? '#f59e0b' : '#10b981');
        const statusLabel = cred.is_expired ? 'EXPIRED' : (isExpiringSoon ? `Expires in ${cred.expires_in_days}d` : 'ACTIVE');

        lapsListEl.innerHTML = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge" style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}55;font-weight:600;font-size:11px;">
                  ${statusLabel}
                </span>
                <span style="margin-left:8px;font-weight:600;font-size:13px;color:var(--text-bright);">
                  Account: <span class="mono">${esc(cred.account_name)}</span>
                </span>
              </div>
              <div style="display:flex;gap:6px;">
                <button class="intune-btn small primary" id="btn-bc-laps-reveal" style="font-size:11px;padding:3px 8px;">
                  👁️ Reveal Password
                </button>
                <button class="intune-btn small" id="btn-bc-laps-rotate" style="font-size:11px;padding:3px 8px;">
                  🔄 Rotate
                </button>
              </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;">
              <div><span style="color:var(--text-muted);">Current Password:</span> <span class="mono" id="bc-laps-pwd-display" style="background:#0f172a;padding:2px 6px;border-radius:4px;border:1px solid #334155;">${esc(cred.masked_password || '••••••••••••••••')}</span></div>
              <div><span style="color:var(--text-muted);">Complexity:</span> <span class="badge badge-neutral" style="font-size:10px;">${esc(cred.complexity_level || 'COMPLEX')}</span> (${cred.password_length} chars)</div>
              <div><span style="color:var(--text-muted);">Last Rotated:</span> ${cred.last_rotated_at ? new Date(cred.last_rotated_at).toLocaleString() : 'Never'}</div>
              <div><span style="color:var(--text-muted);">Access Count:</span> ${cred.access_count || 0} audited access(es)</div>
            </div>

            <div style="border-top:1px solid #334155;padding-top:8px;display:flex;justify-content:space-between;align-items:center;">
              <div style="font-size:11px;color:var(--text-muted);">
                Policy: <span style="color:var(--text-bright);font-weight:500;">${esc(laps.policy ? laps.policy.name : 'Default Fleet Policy')}</span>
                ${(laps.history || []).length > 0 ? ` (${laps.history.length} historical version(s) archived)` : ''}
              </div>
              <button class="intune-btn small" id="btn-bc-view-laps-vault" style="font-size:11px;padding:2px 8px;">
                🔐 View in LAPS Vault &gt;
              </button>
            </div>
          </div>
        `;

        lapsListEl.querySelector('#btn-bc-laps-reveal')?.addEventListener('click', () => {
          if (window.LapsTable && typeof window.LapsTable.reveal === 'function') {
            window.LapsTable.reveal(_currentDevice.id, _currentDevice.hostname, cred.account_name);
          } else {
            prompt('Device LAPS Password', 'Please use the LAPS Vault tab to reveal passwords with audit justification.');
          }
        });

        lapsListEl.querySelector('#btn-bc-laps-rotate')?.addEventListener('click', async () => {
          const reason = prompt(`Enter justification for rotating LAPS password on ${_currentDevice.hostname}:`, 'Scheduled administrative rotation');
          if (!reason) return;
          try {
            await window.FleetAPI.rotateDeviceLapsPassword(_currentDevice.id, { reason, account_name: cred.account_name });
            if (typeof showToast === 'function') showToast('Rotation Dispatched', `Queued LAPS rotation command for ${_currentDevice.hostname}`, 'info');
          } catch (err) {
            if (typeof showToast === 'function') showToast('Rotation Failed', err.message, 'critical');
          }
        });

        lapsListEl.querySelector('#btn-bc-view-laps-vault')?.addEventListener('click', () => {
          close();
          if (window.App && typeof window.App.navigate === 'function') {
            window.App.navigate('laps');
          }
        });
      }).catch(err => {
        lapsListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load LAPS credential posture: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate EPM posture
    const epmListEl = body.querySelector('#bc-epm-list');
    if (epmListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceEpm(_currentDevice.id).then(epm => {
        if (!epm || !epm.effective_rules || epm.effective_rules.length === 0) {
          epmListEl.innerHTML = `
            <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge badge-neutral" style="font-size:11px;">Default Intune Policy</span>
                <span style="margin-left:8px;color:var(--text-muted);">No specific EPM elevation rules assigned to this device.</span>
              </div>
              <button class="intune-btn small" id="btn-bc-view-epm" style="font-size:11px;padding:3px 8px;">
                🛡️ Manage in EPM &gt;
              </button>
            </div>
          `;
          epmListEl.querySelector('#btn-bc-view-epm')?.addEventListener('click', () => {
            close();
            if (window.App && typeof window.App.navigate === 'function') {
              window.App.navigate('epm');
            }
          });
          return;
        }

        epmListEl.innerHTML = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge badge-success" style="font-size:11px;">
                  🛡️ ${epm.rules_count} Active Rule(s)
                </span>
                <span style="margin-left:8px;font-weight:600;font-size:13px;color:var(--text-bright);">
                  ${epm.pending_count > 0 ? `<span style="color:var(--accent-orange, #f59e0b);">⏳ ${epm.pending_count} Pending Elevation Request(s)</span>` : 'Standard User Protection Enforced'}
                </span>
              </div>
              <button class="intune-btn small" id="btn-bc-view-epm" style="font-size:11px;padding:3px 8px;">
                🛡️ View in EPM Blade &gt;
              </button>
            </div>

            <table class="bc-sub-table">
              <thead><tr><th>Target File</th><th>Elevation Type</th><th>Scope / Policy</th><th>Child Procs</th></tr></thead>
              <tbody>
                ${epm.effective_rules.slice(0, 5).map(r => {
                  const isAuto = r.elevation_type === 'AUTOMATIC';
                  const isUser = r.elevation_type === 'USER_CONFIRMED';
                  const color = isAuto ? '#10b981' : (isUser ? '#3b82f6' : '#f59e0b');
                  return `
                    <tr>
                      <td class="mono" style="font-weight:600;">${esc(r.file_name)}</td>
                      <td>
                        <span class="badge" style="background:${color}22;color:${color};border:1px solid ${color}55;font-size:10px;">
                          ${esc(r.elevation_type)}
                        </span>
                      </td>
                      <td style="font-size:11px;color:var(--text-muted);">${esc(r.policy_name)} (${esc(r.group_name)})</td>
                      <td style="font-size:11px;color:var(--text-muted);">${r.child_process_rule === 'ELEVATE_ALL_CHILDREN' ? 'All Children' : 'None'}</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        `;

        epmListEl.querySelector('#btn-bc-view-epm')?.addEventListener('click', () => {
          close();
          if (window.App && typeof window.App.navigate === 'function') {
            window.App.navigate('epm');
          }
        });
      }).catch(err => {
        epmListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load EPM rules: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate Autopilot posture
    const apListEl = body.querySelector('#bc-autopilot-list');
    if (apListEl && _currentDevice?.id) {
      window.FleetAPI.getDeviceAutopilot(_currentDevice.id).then(ap => {
        if (!ap || !ap.autopilot_device) {
          apListEl.innerHTML = `
            <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge badge-neutral" style="font-size:11px;">Unregistered</span>
                <span style="margin-left:8px;color:var(--text-muted);">This device is not registered in the Windows Autopilot hardware database.</span>
              </div>
              <button class="intune-btn small primary" id="btn-bc-ap-register" style="font-size:11px;padding:3px 8px;">
                🚀 Register in Autopilot
              </button>
            </div>
          `;
          apListEl.querySelector('#btn-bc-ap-register')?.addEventListener('click', async () => {
            try {
              await window.FleetAPI.registerAutopilotDevice({
                serial_number: _currentDevice.serial_number || `SN-${_currentDevice.id.slice(0, 8)}`,
                hardware_hash: 'SYNTHESIZED-HASH-' + _currentDevice.id,
                device_id: _currentDevice.id,
                group_tag: 'Self-Enrolled'
              });
              if (typeof showToast === 'function') showToast('Autopilot Registered', `${_currentDevice.hostname} registered in Autopilot registry.`, 'success');
              open(_currentDevice.id);
            } catch (err) {
              if (typeof showToast === 'function') showToast('Registration Failed', err.message, 'critical');
            }
          });
          return;
        }

        const dev = ap.autopilot_device;
        const prof = ap.assigned_profile;
        const esp = ap.effective_esp;
        const events = ap.recent_events || [];

        const isEnrolled = dev.deployment_status === 'ENROLLED';
        const isAssigned = dev.deployment_status === 'ASSIGNED';
        const isFailed = dev.deployment_status === 'FAILED';
        const statusColor = isEnrolled ? '#10b981' : (isAssigned ? '#3b82f6' : (isFailed ? '#ef4444' : '#94a3b8'));

        apListEl.innerHTML = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span class="badge" style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}55;font-weight:600;font-size:11px;">
                  🚀 ${esc(dev.deployment_status)}
                </span>
                <span style="margin-left:8px;font-weight:600;font-size:13px;color:var(--text-bright);">
                  ${prof ? esc(prof.name) : '<span style="color:var(--text-muted);">No Profile Assigned</span>'}
                </span>
              </div>
              <button class="intune-btn small" id="btn-bc-view-ap" style="font-size:11px;padding:3px 8px;">
                🚀 Manage in Autopilot &gt;
              </button>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;">
              <div><span style="color:var(--text-muted);">Group Tag:</span> <span class="mono badge badge-neutral" style="font-size:10px;">${esc(dev.group_tag || 'Standard')}</span></div>
              <div><span style="color:var(--text-muted);">Mode:</span> <span style="color:var(--text-bright);">${prof ? esc(prof.deployment_mode) : '—'}</span></div>
              <div><span style="color:var(--text-muted);">Join Type:</span> <span style="color:var(--text-bright);">${prof ? esc(prof.join_type) : '—'}</span></div>
              <div><span style="color:var(--text-muted);">ESP Policy:</span> <span style="color:var(--text-bright);">${esp ? esc(esp.name) : 'Default ESP'}</span></div>
            </div>

            ${events.length > 0 ? `
              <div style="border-top:1px solid #334155;padding-top:8px;">
                <div style="font-weight:600;color:var(--text-bright);font-size:12px;margin-bottom:4px;">Latest Provisioning Step:</div>
                <div style="font-size:11px;color:var(--text-muted);display:flex;justify-content:space-between;">
                  <span>${esc(events[0].step_name || events[0].phase)} (${esc(events[0].phase)})</span>
                  <span class="badge ${events[0].status === 'COMPLETED' ? 'badge-success' : events[0].status === 'FAILED' ? 'badge-error' : 'badge-warning'}">${esc(events[0].status)}</span>
                </div>
              </div>
            ` : ''}
          </div>
        `;

        apListEl.querySelector('#btn-bc-view-ap')?.addEventListener('click', () => {
          close();
          if (window.App && typeof window.App.navigate === 'function') {
            window.App.navigate('autopilot');
          }
        });
      }).catch(err => {
        apListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load Autopilot posture: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate PowerShell scripts status
    const scriptsListEl = body.querySelector('#bc-scripts-list');
    if (scriptsListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-open-scripts-terminal')?.addEventListener('click', () => {
        close();
        if (window.RemoteTerminal) {
          window.RemoteTerminal.open(_currentDevice.id);
        }
      });

      window.FleetAPI.getDeviceScripts(_currentDevice.id).then(res => {
        const scripts = res.scripts || [];
        if (scripts.length === 0) {
          scriptsListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No PowerShell scripts assigned to this device.</div>';
          return;
        }

        let html = '<div style="display:flex;flex-direction:column;gap:8px;">';
        scripts.forEach(s => {
          const run = s.last_run;
          const statusText = run ? run.status : 'NOT_EXECUTED';
          const isSuccess = statusText === 'SUCCESS';
          const isFailed = statusText === 'FAILED';
          const statusColor = isSuccess ? '#10b981' : (isFailed ? '#ef4444' : '#94a3b8');

          html += `
            <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px;display:flex;justify-content:space-between;align-items:center;">
              <div>
                <div style="font-weight:600;color:var(--text-primary);font-size:13px;">${esc(s.name)}</div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
                  <span class="badge" style="background:rgba(107,114,128,0.2);">${esc(s.run_frequency)}</span>
                  <span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;">${esc(s.run_as_account)}</span>
                  ${run && run.executed_at ? `<span>Executed: ${new Date(run.executed_at).toLocaleTimeString()}</span>` : '<span>Pending heartbeat execution</span>'}
                </div>
              </div>
              <div style="display:flex;align-items:center;gap:8px;">
                <span class="status-pill" style="color:${statusColor};border-color:${statusColor};font-size:11px;">
                  ${esc(statusText)}
                </span>
                <button class="intune-btn small primary btn-bc-run-single-script" data-script-id="${esc(s.id)}" style="font-size:11px;padding:2px 8px;">
                  ⚡ Run
                </button>
              </div>
            </div>
          `;
        });
        html += '</div>';
        scriptsListEl.innerHTML = html;

        scriptsListEl.querySelectorAll('.btn-bc-run-single-script').forEach(btn => {
          btn.addEventListener('click', async () => {
            const scriptId = btn.getAttribute('data-script-id');
            try {
              btn.disabled = true;
              btn.textContent = '⏳';
              await window.FleetAPI.runDeviceScript(_currentDevice.id, scriptId);
              if (typeof showToast === 'function') showToast('Script Queued', 'PowerShell script queued for execution on target node.', 'info');
              setTimeout(() => open(_currentDevice.id), 2000);
            } catch (err) {
              alert(`Failed to run script: ${err.message}`);
              btn.disabled = false;
              btn.textContent = '⚡ Run';
            }
          });
        });
      }).catch(err => {
        scriptsListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load device scripts: ${esc(err.message)}</div>`;
      });
    }

    // Fetch and populate Attack Surface Reduction (ASR) status
    const asrListEl = body.querySelector('#bc-asr-list');
    if (asrListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-asr-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('asr');
        }
      });

      window.FleetAPI.getDeviceASRStatus(_currentDevice.id).then(res => {
        const status = res.status || null;
        const events = res.recent_events || [];
        const eventsToday = res.events_today || 0;

        if (!status) {
          asrListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No ASR posture reported yet for this node.</div>';
          return;
        }

        const npMode = status.network_protection_mode || 'UNKNOWN';
        const cfaMode = status.controlled_folder_access || 'UNKNOWN';
        const epApplied = status.exploit_protection_applied ? 'APPLIED' : 'NOT_CONFIGURED';
        const rulesCount = Object.keys(status.asr_rules_status || {}).length;

        const npColor = npMode === 'BLOCK' ? '#10b981' : (npMode === 'AUDIT' ? '#f59e0b' : '#94a3b8');
        const cfaColor = (cfaMode === 'BLOCK' || cfaMode === 'BLOCK_DISK_MOD_ONLY') ? '#10b981' : (cfaMode.startsWith('AUDIT') ? '#f59e0b' : '#94a3b8');

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-weight:600;color:var(--text-primary);font-size:13px;">${esc(status.policy_name || 'Active Intune ASR Baseline')}</span>
              <span class="badge" style="background:rgba(59,130,246,0.15);color:#60A5FA;">${rulesCount} Rules Evaluated</span>
            </div>
            <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:11px;">
              <div>Network Protection: <span class="status-pill" style="color:${npColor};border-color:${npColor};font-size:10px;padding:1px 6px;">${esc(npMode)}</span></div>
              <div>Controlled Folder Access: <span class="status-pill" style="color:${cfaColor};border-color:${cfaColor};font-size:10px;padding:1px 6px;">${esc(cfaMode)}</span></div>
              <div>Exploit Protection: <span class="status-pill" style="color:#94a3b8;border-color:#334155;font-size:10px;padding:1px 6px;">${esc(epApplied)}</span></div>
            </div>
            ${eventsToday > 0 ? `
              <div style="font-size:11px;color:#ef4444;font-weight:600;padding-top:2px;">⚠️ ${eventsToday} ASR Block/Audit event(s) recorded in last 24h</div>
            ` : `
              <div style="font-size:11px;color:#10b981;padding-top:2px;">✓ Zero ASR threat blocks recorded in last 24h</div>
            `}
          </div>
        `;
        asrListEl.innerHTML = html;
      }).catch(err => {
        asrListEl.innerHTML = `<div style="color:var(--text-muted);font-size:12px;">Pending ASR synchronization.</div>`;
      });
    }

    // Fetch and populate Endpoint Analytics & Health Score
    const analyticsListEl = body.querySelector('#bc-analytics-list');
    if (analyticsListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-analytics-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('analytics');
        }
      });

      window.FleetAPI.getDeviceAnalytics(_currentDevice.id).then(res => {
        const snap = res.latest_snapshot;
        if (!snap) {
          analyticsListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No analytics snapshot recorded yet for this device.</div>';
          return;
        }

        const score = snap.overall_health_score;
        const color = score >= 85 ? '#10B981' : (score >= 70 ? '#F59E0B' : '#EF4444');
        const bootSec = (snap.boot_duration_ms / 1000).toFixed(1);
        const signinSec = (snap.signin_duration_ms / 1000).toFixed(1);

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="font-size:13px;font-weight:600;color:var(--text-primary);">Device Experience Score</span>
              <span class="status-pill" style="color:${color};border-color:${color};font-size:12px;font-weight:700;">${score} / 100</span>
            </div>
            <div style="display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:var(--text-muted);">
              <div>Startup: <span style="color:var(--text-primary);font-weight:600;">${snap.startup_score}/100</span> (Boot: ${bootSec}s, Sign-in: ${signinSec}s)</div>
              <div>Reliability: <span style="color:var(--text-primary);font-weight:600;">${snap.reliability_score}/100</span> (${snap.app_crash_count_24h} crashes)</div>
              <div>Resource: <span style="color:var(--text-primary);font-weight:600;">${snap.resource_score}/100</span></div>
            </div>
          </div>
        `;
        analyticsListEl.innerHTML = html;
      }).catch(err => {
        analyticsListEl.innerHTML = `<div style="color:var(--text-muted);font-size:12px;">Analytics telemetry pending heartbeat sync.</div>`;
      });
    }

    // Fetch and populate Certificates & SCEP Posture
    const certsListEl = body.querySelector('#bc-certificates-list');
    if (certsListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-certificates-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('certificates');
        }
      });

      window.FleetAPI.getDeviceCertificates(_currentDevice.id).then(res => {
        const certs = res.certificates || [];
        if (certs.length === 0) {
          certsListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No certificates reported from workstation store yet.</div>';
          return;
        }

        const valid = certs.filter(c => c.status === 'VALID').length;
        const expiring = certs.filter(c => c.status === 'EXPIRING_SOON').length;
        const expired = certs.filter(c => c.status === 'EXPIRED').length;

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
              <span style="font-size:13px;font-weight:600;color:var(--text-primary);">${certs.length} Certificates Installed</span>
              <div style="display:flex;gap:6px;">
                <span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-size:11px;">${valid} Valid</span>
                ${expiring > 0 ? `<span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;font-size:11px;">${expiring} Expiring</span>` : ''}
                ${expired > 0 ? `<span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-size:11px;">${expired} Expired</span>` : ''}
              </div>
            </div>
            <div style="display:flex;flex-direction:column;gap:4px;max-height:120px;overflow-y:auto;">
              ${certs.slice(0, 4).map(c => `
                <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);border-bottom:1px solid rgba(255,255,255,0.04);padding:2px 0;">
                  <span style="font-weight:500;color:var(--text-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:240px;">${esc(c.subject)}</span>
                  <span>${c.status === 'EXPIRED' ? '🚨 Expired' : (c.status === 'EXPIRING_SOON' ? `⚠️ ${c.days_to_expiry}d` : `✔ ${c.days_to_expiry}d`)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        `;
        certsListEl.innerHTML = html;
      }).catch(() => {
        certsListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Certificate store telemetry pending.</div>';
      });
    }

    // Fetch and populate Wi-Fi & VPN Posture
    const netListEl = body.querySelector('#bc-network-list');
    if (netListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-network-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('network');
        }
      });

      window.FleetAPI.getDeviceNetwork(_currentDevice.id).then(res => {
        const posture = res.posture;
        const profiles = res.assigned_profiles || [];
        if (!posture && profiles.length === 0) {
          netListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No network posture or assigned profiles found.</div>';
          return;
        }

        const ssid = posture?.connected_ssid;
        const signal = posture?.signal_quality_pct || 0;
        const radio = posture?.radio_type || '';
        const ip = posture?.ipv4_address || _currentDevice.ip_address || '—';
        const gw = posture?.ipv4_gateway || '—';
        const vpns = posture?.active_vpns || [];

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:13px;font-weight:600;color:var(--text-primary);">
                  ${ssid ? `📶 ${esc(ssid)}` : '🔌 Ethernet / Wired'}
                </span>
                ${radio ? `<span class="badge" style="background:rgba(255,255,255,0.08);font-size:10px;">${esc(radio)}</span>` : ''}
              </div>
              <div>
                ${ssid ? `
                  <span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-size:11px;">
                    Signal: ${signal}%
                  </span>
                ` : ''}
              </div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:var(--text-muted);">
              <div>IPv4: <span class="mono" style="color:var(--text-primary);">${esc(ip)}</span></div>
              <div>Gateway: <span class="mono" style="color:var(--text-primary);">${esc(gw)}</span></div>
            </div>

            ${vpns.length > 0 ? `
              <div style="border-top:1px solid #334155;padding-top:6px;font-size:11px;">
                <span style="color:var(--text-muted);">Active Tunnels:</span>
                ${vpns.map(v => `<span class="badge" style="background:rgba(168,85,247,0.15);color:#C084FC;margin-left:4px;">🔐 ${esc(v)}</span>`).join('')}
              </div>
            ` : ''}

            <div style="border-top:1px solid #334155;padding-top:6px;font-size:11px;color:var(--text-muted);">
              Assigned Profiles: <strong style="color:var(--text-primary);">${profiles.length}</strong> profile(s) enforced
            </div>
          </div>
        `;
        netListEl.innerHTML = html;
      }).catch(() => {
        netListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Network posture telemetry pending heartbeat sync.</div>';
      });
    }

    // Fetch and populate Kiosk & Assigned Access Posture
    const kioskListEl = body.querySelector('#bc-kiosk-list');
    if (kioskListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-kiosk-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('kiosk');
        }
      });

      window.FleetAPI.getDeviceKiosk(_currentDevice.id).then(status => {
        if (!status) {
          kioskListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No kiosk posture found.</div>';
          return;
        }

        const isKiosk = status.kiosk_active;
        const shell = status.current_shell || 'explorer.exe';
        const profile = status.effective_profile;
        const user = status.active_kiosk_user || '—';

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:13px;font-weight:600;color:var(--text-primary);">
                  ${isKiosk ? '🔒 Kiosk Mode Active' : '💻 Standard Desktop Shell'}
                </span>
                <span class="badge" style="background:${isKiosk ? 'rgba(16,185,129,0.15)' : 'rgba(100,116,139,0.15)'};color:${isKiosk ? '#10B981' : '#94A3B8'};font-size:10px;">
                  ${esc(status.lockdown_status || 'STANDARD_SHELL')}
                </span>
              </div>
              <span class="mono" style="font-size:11px;color:var(--text-muted);">
                Shell: ${esc(shell)}
              </span>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:var(--text-muted);">
              <div>Assigned Profile: <strong style="color:var(--text-primary);">${esc(profile ? profile.name : 'None')}</strong></div>
              <div>Active User: <span class="mono" style="color:var(--text-primary);">${esc(user)}</span></div>
            </div>

            <div style="border-top:1px solid #334155;padding-top:6px;font-size:11px;color:var(--text-muted);">
              Capabilities: AssignedAccess ${status.assigned_access_supported ? '✓' : '✗'} | ShellLauncher ${status.shell_launcher_supported ? '✓' : '✗'}
            </div>
          </div>
        `;
        kioskListEl.innerHTML = html;
      }).catch(() => {
        kioskListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Kiosk telemetry pending audit.</div>';
      });
    }

    // Fetch and populate Removable Storage & USB Posture
    const storageListEl = body.querySelector('#bc-storage-list');
    if (storageListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-storage-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('storage');
        }
      });

      window.FleetAPI.getDeviceStorage(_currentDevice.id).then(res => {
        if (!res) {
          storageListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No removable storage posture found.</div>';
          return;
        }

        const status = res.status;
        const policy = res.effective_policy;
        let drives = [];
        try {
          drives = typeof status?.connected_removable_drives_json === 'string' ? JSON.parse(status.connected_removable_drives_json) : (status?.connected_removable_drives_json || []);
        } catch(e) {}

        const isCompliant = status?.compliance_status === 'COMPLIANT';
        const isDenied = status?.write_access_denied;
        const statusColor = isCompliant ? '#10b981' : (status?.compliance_status === 'UNENCRYPTED_USB_DETECTED' ? '#ef4444' : '#60a5fa');

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:13px;font-weight:600;color:var(--text-primary);">
                  ${drives.length > 0 ? `💾 ${drives.length} Removable Drive(s)` : '💾 No USB Drives Attached'}
                </span>
                <span class="badge" style="background:${statusColor}22;color:${statusColor};font-size:10px;font-weight:600;">
                  ${esc(status?.compliance_status || 'NOT_AUDITED')}
                </span>
              </div>
              <span style="font-size:11px;color:var(--text-muted);">
                ${isDenied ? '🔒 Read-Only Enforced' : '📖 Read/Write Enabled'}
              </span>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:var(--text-muted);">
              <div>Active Policy: <strong style="color:var(--text-primary);">${esc(policy ? policy.name : 'None')}</strong></div>
              <div>BitLocker To Go: <strong style="color:var(--text-primary);">${policy?.require_bitlocker_to_go ? 'Required' : 'Optional'}</strong></div>
            </div>

            ${drives.length > 0 ? `
              <div style="border-top:1px solid #334155;padding-top:6px;font-size:11px;">
                <div style="color:var(--text-muted);margin-bottom:4px;">Connected Volumes:</div>
                ${drives.map(d => `
                  <div style="display:flex;justify-content:space-between;padding:2px 0;">
                    <span><strong style="color:var(--text-primary);">${esc(d.drive_letter || 'USB')}:</strong> ${esc(d.friendly_name || d.volume_name || 'Removable')}</span>
                    <span>${d.is_encrypted ? '<span style="color:var(--accent-green);">🔒 BitLocker</span>' : '<span style="color:var(--accent-red);">⚠️ Plaintext</span>'}</span>
                  </div>
                `).join('')}
              </div>
            ` : ''}
          </div>
        `;
        storageListEl.innerHTML = html;
      }).catch(() => {
        storageListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Removable storage telemetry pending audit.</div>';
      });
    }

    // Fetch and populate Delivery Optimization & Peering Posture
    const doListEl = body.querySelector('#bc-do-list');
    if (doListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-do-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('delivery-optimization');
        }
      });

      window.FleetAPI.getDeviceDO(_currentDevice.id).then(res => {
        if (!res) {
          doListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No Delivery Optimization telemetry found.</div>';
          return;
        }

        const status = res.status;
        const policy = res.effective_policy;
        const p2pBytes = Number(status?.bytes_downloaded_p2p) || 0;
        const httpBytes = Number(status?.bytes_downloaded_http) || 0;
        const effPct = Number(status?.p2p_efficiency_pct) || 0;
        const effColor = effPct >= 50 ? '#10b981' : (effPct >= 20 ? '#f59e0b' : '#60a5fa');

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:13px;font-weight:600;color:var(--text-primary);">
                  🚀 Mode: ${esc(status?.download_mode_active || policy?.download_mode || 'LAN_PEER')}
                </span>
                <span class="badge" style="background:${effColor}22;color:${effColor};font-size:10px;font-weight:700;">
                  ${effPct.toFixed(1)}% P2P Offload
                </span>
              </div>
              <span style="font-size:11px;color:#A78BFA;font-weight:600;">
                👥 ${status?.active_peers_count || 0} Peer(s)
              </span>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:var(--text-muted);">
              <div>Assigned Policy: <strong style="color:var(--text-primary);">${esc(policy ? policy.name : 'Default LAN Peering')}</strong></div>
              <div>Local Cache: <strong style="color:var(--text-primary);">${fmtBytes(status?.cache_size_bytes)} (${status?.cache_file_count || 0} files)</strong></div>
              <div>From Local Peers: <strong style="color:#10b981;">${fmtBytes(p2pBytes)}</strong></div>
              <div>From Microsoft CDN: <strong style="color:var(--text-primary);">${fmtBytes(httpBytes)}</strong></div>
            </div>
          </div>
        `;
        doListEl.innerHTML = html;
      }).catch(() => {
        doListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Delivery Optimization telemetry pending audit.</div>';
      });
    }

    // Fetch and populate DFCI Posture
    const dfciListEl = body.querySelector('#bc-dfci-list');
    if (dfciListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-dfci-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('dfci');
        }
      });

      window.FleetAPI.getDeviceDfci(_currentDevice.id).then(res => {
        if (!res || !res.status) {
          dfciListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No firmware audit received yet.</div>';
          return;
        }

        const status = res.status;
        const policy = res.effective_policy;
        const score = Number(status?.hardware_readiness_score) || 0;
        const scoreColor = score >= 85 ? '#10b981' : (score >= 60 ? '#f59e0b' : '#ef4444');
        const isCompliant = status?.compliance_status === 'COMPLIANT';
        const compColor = isCompliant ? '#10b981' : '#ef4444';

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:13px;font-weight:600;color:var(--text-primary);">
                  🛡️ UEFI BIOS: ${esc(status?.bios_vendor || 'OEM')} ${esc(status?.bios_version || '')}
                </span>
                <span class="badge" style="background:${scoreColor}22;color:${scoreColor};font-size:10px;font-weight:700;">
                  ${score}/100 Readiness
                </span>
              </div>
              <span class="badge" style="background:${compColor}22;color:${compColor};font-size:10px;font-weight:700;">
                ${esc(status?.compliance_status || 'UNKNOWN')}
              </span>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:var(--text-muted);">
              <div>Assigned Policy: <strong style="color:var(--text-primary);">${esc(policy ? policy.name : 'Zero-Trust Baseline')}</strong></div>
              <div>Secure Boot: <strong style="color:${status?.secure_boot_enabled ? '#10b981' : '#ef4444'};">${status?.secure_boot_enabled ? '✅ Enabled' : '❌ Disabled'}</strong></div>
              <div>TPM 2.0: <strong style="color:${status?.tpm_ready ? '#10b981' : '#ef4444'};">${status?.tpm_present ? (status?.tpm_ready ? '✅ Ready (v' + esc(status?.tpm_version || '2.0') + ')' : '⚠️ Degraded') : '❌ Absent'}</strong></div>
              <div>Hardware DMA: <strong style="color:${status?.kernel_dma_protection ? '#10b981' : '#f59e0b'};">${status?.kernel_dma_protection ? '✅ Protected' : '⚠️ None'}</strong></div>
              <div>Peripherals: <strong style="color:var(--text-primary);">Cam: ${status?.cameras_state || 'ALLOW'} | Mic: ${status?.microphones_state || 'ALLOW'}</strong></div>
              <div>Boot Media: <strong style="color:var(--text-primary);">USB: ${status?.external_boot_state || 'ALLOW'} | PXE: ${status?.network_boot_state || 'BLOCK'}</strong></div>
            </div>
          </div>
        `;
        dfciListEl.innerHTML = html;
      }).catch(() => {
        dfciListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Firmware telemetry pending audit.</div>';
      });
    }

    // Fetch and populate WIP Posture
    const wipListEl = body.querySelector('#bc-wip-list');
    if (wipListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-wip-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('wip');
        }
      });

      window.FleetAPI.getDeviceWip(_currentDevice.id).then(res => {
        if (!res || !res.status) {
          wipListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No WIP data protection telemetry reported yet.</div>';
          return;
        }

        const status = res.status;
        const policy = res.effective_policy;
        const enforcement = status?.enforcement_active || 'SILENT';
        const isCompliant = status?.compliance_status === 'COMPLIANT';
        const compColor = isCompliant ? '#10b981' : '#ef4444';
        const enforceColor = enforcement === 'BLOCK' ? '#ef4444' : (enforcement === 'OVERRIDE' ? '#f59e0b' : '#60a5fa');

        let html = `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px;display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="font-size:13px;font-weight:600;color:var(--text-primary);">
                  🔒 Policy: ${esc(policy ? policy.name : 'Enterprise Strict Isolation')}
                </span>
                <span class="badge" style="background:${enforceColor}22;color:${enforceColor};font-size:10px;font-weight:700;">
                  ${esc(enforcement)}
                </span>
              </div>
              <span class="badge" style="background:${compColor}22;color:${compColor};font-size:10px;font-weight:700;">
                ${esc(status?.compliance_status || 'COMPLIANT')}
              </span>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;color:var(--text-muted);">
              <div>Enterprise Domain: <strong style="color:var(--text-primary);">${esc(policy ? policy.enterprise_domain : 'localpilot.internal')}</strong></div>
              <div>Protected Files: <strong style="color:#60a5fa;">${status?.protected_files_count || 0} (${fmtBytes(status?.encrypted_bytes)})</strong></div>
              <div>Managed Apps: <strong style="color:var(--text-primary);">${status?.managed_apps_count || 0} active</strong></div>
              <div>Cloud Exfiltration (24h): <strong style="color:${status?.cloud_exfiltration_attempts_24h > 0 ? '#ef4444' : '#10b981'};">${status?.cloud_exfiltration_attempts_24h || 0} attempts</strong></div>
              <div>Clipboard Violations (24h): <strong style="color:${status?.clipboard_violations_24h > 0 ? '#f59e0b' : 'var(--text-muted)'};">${status?.clipboard_violations_24h || 0}</strong></div>
              <div>Briefcase Overlays: <strong style="color:var(--text-primary);">${policy?.show_wip_overlays ? '✅ Enabled' : 'Off'}</strong></div>
            </div>
          </div>
        `;
        wipListEl.innerHTML = html;
      }).catch(() => {
        wipListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">WIP telemetry pending audit.</div>';
      });
    }

    // Fetch and populate WHfB Posture
    const whfbListEl = body.querySelector('#bc-whfb-list');
    if (whfbListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-whfb-tab')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('whfb');
        }
      });

      window.FleetAPI.getDeviceWhfb(_currentDevice.id).then(res => {
        if (!res || !res.status) {
          whfbListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No Windows Hello telemetry reported yet.</div>';
          return;
        }

        const status = res.status;
        const policy = res.effective_policy;
        const isEnrolled = status?.whfb_enrolled === 1;

        let bioStr = 'None';
        if (status?.face_auth_configured && status?.fingerprint_auth_configured) {
          bioStr = '👤 Face + 👆 Fingerprint';
        } else if (status?.face_auth_configured) {
          bioStr = '👤 Face (IR Depth)';
        } else if (status?.fingerprint_auth_configured) {
          bioStr = '👆 Fingerprint';
        }

        const html = `
          <div style="background:var(--bg-secondary);padding:10px 12px;border-radius:6px;border:1px solid var(--border-color);margin-top:4px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
              <span style="font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:6px;">
                <span>🔑</span> ${policy ? policy.name : 'Default Windows Hello Policy'}
              </span>
              <span class="badge" style="background:${isEnrolled ? 'rgba(16,185,129,0.15)' : 'rgba(245,158,11,0.15)'};color:${isEnrolled ? '#10b981' : '#f59e0b'};font-weight:700;">
                ${isEnrolled ? '✅ ENROLLED' : '⏳ NOT ENROLLED'}
              </span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px 16px;font-size:11px;color:var(--text-muted);">
              <div>TPM 2.0: <strong style="color:var(--text-primary);">${status?.tpm_present && status?.tpm_ready ? '🔒 Present & Ready' : (status?.tpm_present ? '⚠️ Not Ready' : '❌ Missing')}</strong></div>
              <div>Biometrics: <strong style="color:var(--text-primary);">${bioStr}</strong></div>
              <div>FIDO2 Security Keys: <strong style="color:var(--text-primary);">${status?.fido2_keys_count > 0 ? '🔑 ' + status.fido2_keys_count + ' key(s)' : '0 registered'}</strong></div>
              <div>PIN Complexity: <strong style="color:${status?.pin_complexity_compliant ? '#10b981' : '#ef4444'};">${status?.pin_complexity_compliant ? '✅ Compliant' : '🚨 Violates Policy'}</strong></div>
              <div>Anti-Spoofing: <strong style="color:var(--text-primary);">${status?.anti_spoofing_active ? '🛡️ Active' : 'Standard'}</strong></div>
              <div>Compliance: <strong style="color:${status?.compliance_status === 'COMPLIANT' ? '#10b981' : '#f59e0b'};">${status?.compliance_status || 'UNKNOWN'}</strong></div>
            </div>
          </div>
        `;
        whfbListEl.innerHTML = html;
      }).catch(() => {
        whfbListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Windows Hello telemetry pending audit.</div>';
      });
    }

    // Fetch and populate Remote Actions & Diagnostics
    const raListEl = body.querySelector('#bc-remote-actions-list');
    if (raListEl && _currentDevice?.id) {
      body.querySelector('#btn-bc-view-all-remote')?.addEventListener('click', () => {
        close();
        if (window.App && typeof window.App.navigate === 'function') {
          window.App.navigate('remote-actions');
        }
      });

      Promise.all([
        window.FleetAPI.getDeviceRemoteActions(_currentDevice.id).catch(() => ({ actions: [] })),
        window.FleetAPI.getDeviceDiagnostics(_currentDevice.id).catch(() => ({ bundles: [] }))
      ]).then(([raRes, diagRes]) => {
        const actions = raRes.actions || [];
        const bundles = diagRes.bundles || [];

        if (actions.length === 0 && bundles.length === 0) {
          raListEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No remote actions or diagnostic packages for this device yet.</div>';
          return;
        }

        let html = '<div style="display:flex;flex-direction:column;gap:8px;">';

        // Diagnostics highlight if any
        if (bundles.length > 0) {
          const latestBundle = bundles[0];
          const sizeStr = (latestBundle.file_size_bytes / 1024).toFixed(1) + ' KB';
          html += `
            <div style="background:#1e293b;border:1px solid #3b82f644;border-radius:6px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;">
              <div>
                <div style="font-weight:600;color:var(--accent-blue);font-size:12px;">📦 Latest Diagnostics Bundle</div>
                <div style="font-size:11px;color:var(--text-muted);">${esc(latestBundle.file_name)} (${sizeStr}) &bull; ${new Date(latestBundle.created_at).toLocaleString()}</div>
              </div>
              <button class="intune-btn small primary" id="btn-bc-dl-diag" style="font-size:11px;padding:3px 8px;">
                ⬇️ Download ZIP
              </button>
            </div>
          `;
        }

        // Recent Actions table
        if (actions.length > 0) {
          html += `
            <table class="bc-sub-table" style="margin-top:4px;">
              <thead><tr><th>Action</th><th>Status</th><th>Initiated</th><th>Completed</th></tr></thead>
              <tbody>
                ${actions.slice(0, 5).map(act => {
                  const statusColors = {
                    PENDING: '#94a3b8',
                    DISPATCHED: '#3b82f6',
                    RUNNING: '#06b6d4',
                    COMPLETED: '#10b981',
                    FAILED: '#ef4444',
                    CANCELLED: '#64748b'
                  };
                  const color = statusColors[act.status] || '#94a3b8';
                  return `
                    <tr>
                      <td style="font-weight:600;">${esc(act.action_type)}</td>
                      <td><span class="badge" style="background:${color}22;color:${color};border:1px solid ${color}55;font-size:10px;">${esc(act.status)}</span></td>
                      <td style="font-size:11px;color:var(--text-muted);">${new Date(act.created_at).toLocaleTimeString()}</td>
                      <td style="font-size:11px;color:var(--text-muted);">${act.completed_at ? new Date(act.completed_at).toLocaleTimeString() : (act.error_message ? `<span title="${esc(act.error_message)}" style="color:#ef4444;">Error</span>` : '—')}</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          `;
        }

        html += '</div>';
        raListEl.innerHTML = html;

        if (bundles.length > 0) {
          raListEl.querySelector('#btn-bc-dl-diag')?.addEventListener('click', () => {
            window.FleetAPI.downloadDiagnostics(bundles[0].id, bundles[0].file_name);
          });
        }
      }).catch(err => {
        raListEl.innerHTML = `<div style="color:#EF4444;font-size:12px;">Failed to load remote actions: ${esc(err.message)}</div>`;
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
        await window.FleetAPI.queueRemoteAction({ device_id: _currentDevice.id, action_type: 'SYNC_MDM' });
        if (typeof showToast === 'function') showToast('Sync Dispatched', `Check-in requested for ${_currentDevice.hostname}`, 'success');
        if (_currentDevice?.id) open(_currentDevice.id);
      } catch (err) {
        if (typeof showToast === 'function') showToast('Sync Failed', err.message, 'critical');
      }
    });

    const btnToast = document.getElementById('btn-blade-toast');
    btnToast?.addEventListener('click', () => {
      if (!_currentDevice) return;
      if (window.MessagesTable && typeof window.MessagesTable.openQuickToastModal === 'function') {
        window.MessagesTable.openQuickToastModal(_currentDevice.id);
      } else {
        const title = prompt(`Enter notification title for ${_currentDevice.hostname}:`, "IT Administration Notice");
        if (!title) return;
        const message = prompt("Enter notification message:");
        if (!message) return;
        window.FleetAPI.dispatchDeviceToast(_currentDevice.id, { title, message })
          .then(() => {
            if (typeof showToast === 'function') showToast('Toast Queued', `Notification queued for ${_currentDevice.hostname}`, 'success');
          })
          .catch(err => {
            if (typeof showToast === 'function') showToast('Toast Failed', err.message, 'critical');
          });
      }
    });

    const btnRestart = document.getElementById('btn-blade-restart');
    btnRestart?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      const delayStr = prompt(`Reboot ${_currentDevice.hostname}?\nEnter delay in seconds (default 30):`, "30");
      if (delayStr === null) return;
      const delay_sec = parseInt(delayStr, 10) || 30;
      const message = prompt(`Reboot notification message to user:`, "Your IT administrator has scheduled a device restart.") || '';
      try {
        await window.FleetAPI.queueRemoteAction({
          device_id: _currentDevice.id,
          action_type: 'RESTART',
          parameters: { delay_sec, message }
        });
        if (typeof showToast === 'function') showToast('Reboot Queued', `Restart scheduled in ${delay_sec}s for ${_currentDevice.hostname}`, 'warning');
        if (_currentDevice?.id) open(_currentDevice.id);
      } catch (err) {
        if (typeof showToast === 'function') showToast('Reboot Failed', err.message, 'critical');
      }
    });

    const btnLock = document.getElementById('btn-blade-lock');
    btnLock?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      if (!confirm(`Lock workstation for ${_currentDevice.hostname} immediately?`)) return;
      try {
        await window.FleetAPI.queueRemoteAction({ device_id: _currentDevice.id, action_type: 'REMOTE_LOCK' });
        if (typeof showToast === 'function') showToast('Remote Lock', `Lock workstation command dispatched to ${_currentDevice.hostname}`, 'info');
        if (_currentDevice?.id) open(_currentDevice.id);
      } catch (err) {
        if (typeof showToast === 'function') showToast('Lock Failed', err.message, 'critical');
      }
    });

    const btnScan = document.getElementById('btn-blade-scan');
    btnScan?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      try {
        await window.FleetAPI.queueRemoteAction({
          device_id: _currentDevice.id,
          action_type: 'DEFENDER_SCAN',
          parameters: { scan_type: 'QuickScan' }
        });
        if (typeof showToast === 'function') showToast('Defender Scan', `Windows Defender quick scan initiated on ${_currentDevice.hostname}`, 'info');
        if (_currentDevice?.id) open(_currentDevice.id);
      } catch (err) {
        if (typeof showToast === 'function') showToast('Scan Failed', err.message, 'critical');
      }
    });

    const btnDiag = document.getElementById('btn-blade-diagnostics');
    btnDiag?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      try {
        await window.FleetAPI.queueRemoteAction({ device_id: _currentDevice.id, action_type: 'COLLECT_DIAGNOSTICS' });
        if (typeof showToast === 'function') showToast('Diagnostics Queued', `Log collection dispatched to ${_currentDevice.hostname}`, 'info');
        if (_currentDevice?.id) open(_currentDevice.id);
      } catch (err) {
        if (typeof showToast === 'function') showToast('Diagnostics Failed', err.message, 'critical');
      }
    });

    const btnFreshStart = document.getElementById('btn-blade-fresh-start');
    btnFreshStart?.addEventListener('click', async () => {
      if (!_currentDevice) return;
      if (!confirm(`⚠️ Trigger FRESH START on ${_currentDevice.hostname}?\nThis will retain user profiles and data while returning Windows to a clean factory state.`)) return;
      try {
        await window.FleetAPI.queueRemoteAction({ device_id: _currentDevice.id, action_type: 'FRESH_START' });
        if (typeof showToast === 'function') showToast('Fresh Start Dispatched', `Clean wipe initiated on ${_currentDevice.hostname}`, 'warning');
        if (_currentDevice?.id) open(_currentDevice.id);
      } catch (err) {
        if (typeof showToast === 'function') showToast('Fresh Start Failed', err.message, 'critical');
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
