/**
 * LocalPilot Fleet — Master Application Controller
 * dashboard/js/app.js
 */

const App = {
  currentTab: 'overview',

  init() {
    this.checkAuth();
    this.bindNavigation();
    this.bindGlobalEvents();
    this.startSSEConnection();
    this.navigate('overview');
  },

  checkAuth() {
    const key = localStorage.getItem('fleet_key');
    const overlay = document.getElementById('setup-overlay');

    if (!key) {
      if (overlay) overlay.style.display = 'flex';
      const submitBtn = document.getElementById('setup-submit-btn');
      submitBtn?.addEventListener('click', () => {
        const inputKey = document.getElementById('setup-fleet-key')?.value.trim();
        const inputUrl = document.getElementById('setup-server-url')?.value.trim();
        const errEl = document.getElementById('setup-error');

        if (!inputKey) {
          if (errEl) errEl.textContent = 'Fleet API Key is required';
          return;
        }

        localStorage.setItem('fleet_key', inputKey);
        if (inputUrl) localStorage.setItem('fleet_server_url', inputUrl);
        if (overlay) overlay.style.display = 'none';
        this.navigate(this.currentTab);
        this.startSSEConnection();
      });
    } else {
      if (overlay) overlay.style.display = 'none';
    }
  },

  bindNavigation() {
    const navItems = document.querySelectorAll('.nav-item, .nav-sub-item');
    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const tab = item.getAttribute('data-tab');
        if (tab) this.navigate(tab);
      });
    });
  },

  navigate(tabName) {
    this.currentTab = tabName;

    // Update active nav item
    document.querySelectorAll('.nav-item, .nav-sub-item').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-tab') === tabName);
    });

    // Update tab pages
    document.querySelectorAll('.tab-page').forEach(page => {
      page.style.display = 'none';
    });

    const activePage = document.getElementById(`tab-${tabName}`);
    if (activePage) activePage.style.display = 'block';

    // Render Tab Content
    switch (tabName) {
      case 'overview':
        if (typeof renderKpiCards === 'function') renderKpiCards();
        if (window.OverviewWidgets) window.OverviewWidgets.render();
        break;
      case 'devices':
        if (typeof renderDeviceTable === 'function') renderDeviceTable();
        break;
      case 'groups':
        if (typeof renderDynamicGroups === 'function') renderDynamicGroups();
        break;
      case 'software':
        if (typeof renderPolicyMatrix === 'function') renderPolicyMatrix();
        break;
      case 'events':
        if (typeof renderActivityFeed === 'function') renderActivityFeed();
        // Clear events badge
        const badge = document.getElementById('nav-events-badge');
        if (badge) badge.classList.add('hidden');
        break;
      case 'remediations':
        if (window.RemediationsTable) window.RemediationsTable.loadData();
        break;
      case 'scripts':
        if (window.ScriptsTable) window.ScriptsTable.init();
        break;
      case 'profiles':
        if (window.ConfigurationProfilesTable) window.ConfigurationProfilesTable.loadData();
        break;
      case 'updates':
        if (window.UpdateRingsTable) window.UpdateRingsTable.loadData();
        break;
      case 'compliance':
        if (window.CompliancePoliciesTable) window.CompliancePoliciesTable.loadData();
        break;
      case 'apps':
        if (window.AppsTable) window.AppsTable.loadData();
        break;
      case 'security':
        if (window.EndpointSecurityTable) window.EndpointSecurityTable.loadData();
        break;
      case 'firewall':
        if (window.FirewallTable) window.FirewallTable.init();
        break;
      case 'bitlocker':
        if (window.BitLockerTable) window.BitLockerTable.init();
        break;
      case 'laps':
        if (window.LapsTable) window.LapsTable.init();
        break;
      case 'epm':
        if (window.EpmTable) window.EpmTable.init();
        break;
      case 'autopilot':
        if (window.AutopilotTable) window.AutopilotTable.init();
        break;
      case 'remote-actions':
        if (window.RemoteActionsTable) window.RemoteActionsTable.init();
        break;
      case 'settings':
        this.renderSettings();
        break;
    }
  },

  bindGlobalEvents() {
    // Cloud Shell terminal top header button
    const terminalBtn = document.getElementById('btn-terminal') || document.querySelector('button[title*="Cloud Shell"]');
    if (terminalBtn) {
      terminalBtn.id = 'btn-terminal';
      terminalBtn.addEventListener('click', () => {
        if (window.RemoteTerminal) window.RemoteTerminal.open();
      });
    }

    // SSE Alert event listener
    document.addEventListener('fleet:event', (e) => {
      const data = e.detail;
      this.playAlertSound(data.severity);
      this.showNotificationToast(data);

      // Increment sidebar badge
      const badge = document.getElementById('nav-events-badge');
      if (badge) {
        badge.classList.remove('hidden');
        const count = parseInt(badge.textContent || '0') + 1;
        badge.textContent = count;
      }

      // Live update if on events tab
      if (this.currentTab === 'events' && typeof loadEventsData === 'function') {
        loadEventsData();
      }
      // Live update if on overview tab
      if (this.currentTab === 'overview') {
        if (typeof renderKpiCards === 'function') renderKpiCards();
        if (window.OverviewWidgets) window.OverviewWidgets.render();
      }
    });

    // Device modal close
    document.getElementById('bc-close-btn')?.addEventListener('click', () => {
      document.getElementById('bc-drawer')?.classList.remove('open');
      document.getElementById('bc-overlay')?.classList.remove('open');
    });
    document.getElementById('bc-overlay')?.addEventListener('click', () => {
      document.getElementById('bc-drawer')?.classList.remove('open');
      document.getElementById('bc-overlay')?.classList.remove('open');
    });
  },

  startSSEConnection() {
    if (typeof startSSE === 'function') {
      startSSE();
    }
  },

  showNotificationToast(data) {
    const title = data.event_type ? data.event_type.replace('_', ' ').toUpperCase() : 'SECURITY ALERT';
    const msg = data.description || `Security event detected on ${data.hostname || 'managed device'}`;
    const severity = data.severity || 'info';
    showToast(`🚨 ${title}`, msg, severity === 'critical' || severity === 'high' ? 'error' : 'warning');
  },

  playAlertSound(severity) {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      if (severity === 'critical') {
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.3);
      } else {
        osc.frequency.setValueAtTime(587.33, ctx.currentTime);
        osc.frequency.setValueAtTime(880, ctx.currentTime + 0.15);
      }

      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);

      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.4);
    } catch {}
  },

  async renderSettings() {
    const container = document.getElementById('settings-container');
    if (!container) return;

    let settings = {};
    try {
      settings = await apiFetch('/api/v1/fleet/settings');
    } catch {}

    container.innerHTML = `
      <div class="intune-blade-header">
        <div class="intune-breadcrumb">Home &gt; Tenant administration &gt; Tenant status</div>
        <div class="intune-title-row">
          <div class="intune-title-icon">⚙️</div>
          <div>
            <h1 class="intune-blade-title">Tenant administration | Tenant status</h1>
            <p class="intune-blade-subtitle">Manage your local master authority, Cloudflare Tunnel reverse proxy, and alert dispatchers</p>
          </div>
        </div>
      </div>

      <div class="intune-settings-layout">
        <!-- Tenant Status Card -->
        <div class="intune-card">
          <div class="intune-card-header">
            <span class="card-icon">🏢</span>
            <h3>Tenant Details & License Status</h3>
          </div>
          <div class="intune-card-body">
            <div class="property-grid">
              <div class="prop-item"><span class="prop-label">Tenant name:</span><strong>${settings.tenant_name || 'LocalPilot Family Fleet'}</strong></div>
              <div class="prop-item"><span class="prop-label">Service status:</span><span class="intune-badge green">✓ Healthy</span></div>
              <div class="prop-item"><span class="prop-label">License level:</span><span class="intune-badge neutral">LocalPilot Suite (Self-Hosted Unlimited)</span></div>
              <div class="prop-item"><span class="prop-label">Authority location:</span><code>${window.location.origin}</code></div>
              <div class="prop-item"><span class="prop-label">Database engine:</span><code>SQLite WAL (node:sqlite)</code></div>
            </div>
          </div>
        </div>

        <!-- Cloudflare Tunnel Configuration Card -->
        <div class="intune-card">
          <div class="intune-card-header">
            <span class="card-icon">☁️</span>
            <h3>Cloudflare Tunnel Reverse Proxy (Zero Trust)</h3>
          </div>
          <div class="intune-card-body">
            <p class="text-secondary" style="margin-bottom:14px;">
              Enables remote family laptops (on school, hotel, or café Wi-Fi) to report back to your Master PC without port forwarding.
            </p>
            <div class="intune-form-group">
              <label class="intune-label">Cloudflare Tunnel Public Hostname</label>
              <input type="text" id="setting-tunnel-host" class="intune-input code-font" placeholder="e.g., fleet.yourdomain.com" value="${settings.cloudflare_tunnel_hostname || ''}" />
            </div>
            <div class="form-hint">
              Run <code>.\\cloudflare\\Generate-TunnelConfig.ps1 -Hostname fleet.yourdomain.com</code> on this PC to configure the connector.
            </div>
            <button class="intune-btn secondary" style="margin-top:10px;" onclick="testTunnelStatus()">⚡ Test Tunnel Endpoint</button>
          </div>
        </div>

        <!-- Notification Webhooks Card -->
        <div class="intune-card">
          <div class="intune-card-header">
            <span class="card-icon">🔔</span>
            <h3>Alert Notification Webhooks</h3>
          </div>
          <div class="intune-card-body">
            <div class="intune-form-group">
              <label class="intune-label">Discord / Slack Webhook URL</label>
              <input type="password" id="setting-webhook-url" class="intune-input secret" placeholder="https://discord.com/api/webhooks/..." value="${settings.webhook_url || ''}" />
            </div>
            <div class="intune-form-group">
              <label class="intune-checkbox-label">
                <input type="checkbox" id="setting-toast-enabled" ${settings.winrt_toast_enabled !== false ? 'checked' : ''} />
                <span>Show native Windows toast notifications on this Master PC</span>
              </label>
            </div>
            <button class="intune-btn primary" style="margin-top:12px;" onclick="saveSettings()">Save Tenant Settings</button>
          </div>
        </div>
      </div>
    `;
  }
};

window.showToast = function(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `intune-toast ${type}`;
  toast.innerHTML = `
    <div class="toast-header">
      <strong>${title}</strong>
      <button class="toast-close" onclick="this.parentElement.parentElement.remove()">&times;</button>
    </div>
    <div class="toast-body">${message}</div>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'fadeOut 0.4s ease forwards';
    setTimeout(() => toast.remove(), 400);
  }, 5000);
};

window.saveSettings = async function() {
  const host = document.getElementById('setting-tunnel-host')?.value.trim();
  const webhook = document.getElementById('setting-webhook-url')?.value.trim();
  const toast = document.getElementById('setting-toast-enabled')?.checked;

  try {
    await apiFetch('/api/v1/fleet/settings', {
      method: 'PUT',
      body: JSON.stringify({
        cloudflare_tunnel_hostname: host,
        webhook_url: webhook,
        winrt_toast_enabled: toast
      })
    });
    showToast('Settings Saved', 'Tenant configuration updated successfully.', 'success');
  } catch (e) {
    alert('Failed to save settings: ' + e.message);
  }
};

window.testTunnelStatus = function() {
  const host = document.getElementById('setting-tunnel-host')?.value.trim();
  if (!host) {
    alert('Please enter a Cloudflare Tunnel hostname first.');
    return;
  }
  showToast('Testing Connector', `Pinging https://${host}/api/v1/health...`, 'info');
  fetch(`https://${host}/api/v1/health`, { mode: 'cors' })
    .then(r => r.json())
    .then(d => {
      showToast('Connector Online', `Cloudflare Tunnel responded: ${d.status}`, 'success');
    })
    .catch(() => {
      showToast('Tunnel Unreachable', 'Could not reach server via tunnel hostname. Check cloudflared service.', 'warning');
    });
};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
