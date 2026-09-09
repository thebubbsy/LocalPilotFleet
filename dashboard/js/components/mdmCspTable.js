/**
 * LocalPilot Fleet — Native Windows MDM Protocol & CSP Dashboard Blade
 * dashboard/js/components/mdmCspTable.js
 *
 * Dimension 5: Native OS Protocol Integration
 * Manages native Windows OMA-DM Configuration Service Providers (CSPs),
 * WMI Bridge Provider (root\cimv2\mdm\dmmap), Autopilot 4K Hardware Hash harvesting,
 * and native RemoteWipe CSP crypto-erasure.
 */

window.MdmCspTable = {
  currentTab: 'csps',
  stats: null,
  csps: [],
  hashes: [],

  async render() {
    const container = document.getElementById('tab-mdm-csp');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header" style="margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h2 style="margin: 0; font-size: 1.4rem; display: flex; align-items: center; gap: 0.5rem;">
            <span>📱</span> Native Windows MDM Protocol &amp; CSP Integration
            <span class="badge badge-success" style="font-size: 0.75rem; padding: 2px 8px; border-radius: 9999px;">Dimension 5</span>
          </h2>
          <p class="text-muted" style="margin: 0.25rem 0 0 0; font-size: 0.85rem;">
            Native Windows OMA-DM CSP execution via WMI Bridge Provider (<code>root\cimv2\mdm\dmmap</code>), Autopilot 4K hardware hashes, and native RemoteWipe CSP WinRE crypto-erasure.
          </p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary btn-sm" onclick="MdmCspTable.refresh()">
            <span>🔄</span> Refresh
          </button>
          <button class="btn btn-primary btn-sm" onclick="MdmCspTable.openNewCspModal()">
            <span>➕</span> Add CSP
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="kpi-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Enforced Native CSPs</div>
          <div class="kpi-value" id="kpi-mdm-csps" style="font-size: 1.6rem; font-weight: 700; color: #38bdf8; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" id="kpi-mdm-csps-sub" style="font-size: 0.75rem; color: #64748b;">OMA-DM Provider Sync</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Autopilot 4K Hashes</div>
          <div class="kpi-value" id="kpi-mdm-hashes" style="font-size: 1.6rem; font-weight: 700; color: #10b981; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">Hardware-Rooted OOBE</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">RemoteWipe CSP Dispatches</div>
          <div class="kpi-value" id="kpi-mdm-wipes" style="font-size: 1.6rem; font-weight: 700; color: #f43f5e; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">WinRE TPM Crypto-Erase</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">OMA-DM Protocol Status</div>
          <div class="kpi-value" id="kpi-mdm-status" style="font-size: 1.3rem; font-weight: 700; color: #a855f7; margin: 0.25rem 0;">OPERATIONAL</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">dmmap WMI Bridge Active</div>
        </div>
      </div>

      <!-- Navigation Sub-tabs -->
      <div class="tabs-nav" style="display: flex; gap: 0.5rem; border-bottom: 1px solid var(--border-color, #334155); margin-bottom: 1rem;">
        <button class="tab-btn ${this.currentTab === 'csps' ? 'active' : ''}" onclick="MdmCspTable.switchTab('csps')" style="padding: 0.5rem 1rem; background: none; border: none; color: ${this.currentTab === 'csps' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${this.currentTab === 'csps' ? '#38bdf8' : 'transparent'}; cursor: pointer; font-weight: 600;">
          📱 Native Windows CSPs
        </button>
        <button class="tab-btn ${this.currentTab === 'autopilot' ? 'active' : ''}" onclick="MdmCspTable.switchTab('autopilot')" style="padding: 0.5rem 1rem; background: none; border: none; color: ${this.currentTab === 'autopilot' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${this.currentTab === 'autopilot' ? '#38bdf8' : 'transparent'}; cursor: pointer; font-weight: 600;">
          🔑 Autopilot 4K Hardware Hashes
        </button>
        <button class="tab-btn ${this.currentTab === 'wipes' ? 'active' : ''}" onclick="MdmCspTable.switchTab('wipes')" style="padding: 0.5rem 1rem; background: none; border: none; color: ${this.currentTab === 'wipes' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${this.currentTab === 'wipes' ? '#38bdf8' : 'transparent'}; cursor: pointer; font-weight: 600;">
          💣 Native RemoteWipe CSP Console
        </button>
      </div>

      <!-- Sub-tab Content Area -->
      <div id="mdm-csp-tab-content">
        ${this.renderCurrentSubTab()}
      </div>
    `;

    await this.loadData();
  },

  async loadData() {
    try {
      const [stats, cspsRes, hashesRes] = await Promise.all([
        window.FleetAPI.getMdmStats().catch(() => null),
        window.FleetAPI.getMdmCsps().catch(() => ({ csps: [] })),
        window.FleetAPI.getAutopilotHardwareHashes().catch(() => ({ hashes: [] }))
      ]);

      this.stats = stats;
      this.csps = cspsRes?.csps || [];
      this.hashes = hashesRes?.hashes || [];

      this.updateKpis();
      const content = document.getElementById('mdm-csp-tab-content');
      if (content) {
        content.innerHTML = this.renderCurrentSubTab();
      }
    } catch (err) {
      console.error('[MdmCspTable] loadData error:', err);
    }
  },

  updateKpis() {
    if (this.stats) {
      const elCsps = document.getElementById('kpi-mdm-csps');
      const elCspsSub = document.getElementById('kpi-mdm-csps-sub');
      const elHashes = document.getElementById('kpi-mdm-hashes');
      const elWipes = document.getElementById('kpi-mdm-wipes');

      if (elCsps) elCsps.textContent = this.stats.enforced_csp_configurations;
      if (elCspsSub) elCspsSub.textContent = `${this.stats.total_csp_configurations} Total Registered`;
      if (elHashes) elHashes.textContent = this.stats.autopilot_4k_hashes?.total || '0';
      if (elWipes) elWipes.textContent = this.stats.native_remote_wipes || '0';
    }
  },

  switchTab(tab) {
    this.currentTab = tab;
    this.render();
  },

  refresh() {
    return this.loadData();
  },

  renderCurrentSubTab() {
    if (this.currentTab === 'csps') return this.renderCspsTab();
    if (this.currentTab === 'autopilot') return this.renderAutopilotTab();
    if (this.currentTab === 'wipes') return this.renderWipesTab();
    return '';
  },

  renderCspsTab() {
    if (!this.csps.length) {
      return `<div class="empty-state" style="text-align: center; padding: 2rem; color: #64748b;">No native CSPs configured</div>`;
    }

    return `
      <div class="table-responsive" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow-x: auto;">
        <table class="table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; text-align: left; color: #94a3b8;">
              <th style="padding: 0.75rem 1rem;">CSP Policy Name</th>
              <th style="padding: 0.75rem 1rem;">Native OMA-DM URI</th>
              <th style="padding: 0.75rem 1rem;">WMI Bridge Class</th>
              <th style="padding: 0.75rem 1rem;">Type / Value</th>
              <th style="padding: 0.75rem 1rem;">Target Group</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${this.csps.map(c => `
              <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 0.75rem 1rem; font-weight: 600; color: #f8fafc;">
                  ${escapeHtml(c.name)}
                  ${c.is_enforced ? '<span class="badge badge-success" style="background:#10b981;color:#fff;font-size:0.65rem;padding:1px 5px;border-radius:4px;margin-left:4px;">ENFORCED</span>' : '<span class="badge badge-secondary" style="font-size:0.65rem;">DISABLED</span>'}
                </td>
                <td style="padding: 0.75rem 1rem; font-family: monospace; color: #38bdf8;">
                  ${escapeHtml(c.csp_uri)}
                </td>
                <td style="padding: 0.75rem 1rem; font-family: monospace; color: #cbd5e1;">
                  ${escapeHtml(c.wmi_class)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span class="badge" style="background: #0f172a; border: 1px solid #334155; color: #f59e0b; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-family: monospace;">
                    ${c.csp_type} (${c.data_type})
                  </span>
                  ${c.target_value ? `<div style="font-size:0.75rem;color:#94a3b8;margin-top:2px;">Value: ${escapeHtml(c.target_value)}</div>` : ''}
                </td>
                <td style="padding: 0.75rem 1rem; color: #94a3b8;">${escapeHtml(c.target_group_id || 'grp-all')}</td>
                <td style="padding: 0.75rem 1rem; text-align: right;">
                  <button class="btn btn-secondary btn-xs" onclick="MdmCspTable.inspectScript('${c.id}')" style="padding: 2px 6px; font-size: 0.7rem; margin-right: 4px;">
                    View WMI Script
                  </button>
                  <button class="btn btn-danger btn-xs" onclick="MdmCspTable.deleteCsp('${c.id}')" style="padding: 2px 6px; font-size: 0.7rem;">
                    Delete
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  renderAutopilotTab() {
    if (!this.hashes.length) {
      return `<div class="empty-state" style="text-align: center; padding: 2rem; color: #64748b;">No Autopilot 4K hardware hashes harvested</div>`;
    }

    return `
      <div class="table-responsive" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow-x: auto;">
        <table class="table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; text-align: left; color: #94a3b8;">
              <th style="padding: 0.75rem 1rem;">Workstation / Hardware</th>
              <th style="padding: 0.75rem 1rem;">SMBIOS UUID &amp; Serial</th>
              <th style="padding: 0.75rem 1rem;">4K Hash Length</th>
              <th style="padding: 0.75rem 1rem;">Enrollment State</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Autopilot CSV Export</th>
            </tr>
          </thead>
          <tbody>
            ${this.hashes.map(h => `
              <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 0.75rem 1rem;">
                  <div style="font-weight: 600; color: #f8fafc;">${escapeHtml(h.hostname || h.device_id)}</div>
                  <div style="font-size: 0.75rem; color: #64748b;">${escapeHtml(h.oem_manufacturer)} ${escapeHtml(h.oem_model)}</div>
                </td>
                <td style="padding: 0.75rem 1rem; font-family: monospace; font-size: 0.75rem; color: #cbd5e1;">
                  <div>UUID: ${escapeHtml(h.smbios_uuid)}</div>
                  <div>SN: ${escapeHtml(h.serial_number)}</div>
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span class="badge" style="background: #0284c7; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 700;">
                    ${h.hash_length} chars (4K Valid)
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span class="badge badge-success" style="background: #10b981; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.7rem;">
                    ${h.enrollment_state}
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem; text-align: right;">
                  <button class="btn btn-primary btn-xs" onclick="MdmCspTable.copyAutopilotHash('${h.device_id}')" style="padding: 2px 6px; font-size: 0.7rem;">
                    📋 Copy 4K Hash
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  },

  renderWipesTab() {
    return `
      <div style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1.5rem; max-width: 700px;">
        <h3 style="margin: 0 0 0.5rem 0; font-size: 1.1rem; color: #f43f5e; display: flex; align-items: center; gap: 0.5rem;">
          <span>💣</span> Native RemoteWipe CSP &amp; WinRE Crypto-Erase Console
        </h3>
        <p style="font-size: 0.85rem; color: #94a3b8; margin: 0 0 1.25rem 0;">
          Invokes the native Windows <code>MDM_RemoteWipe</code> CSP (<code>./Vendor/MSFT/RemoteWipe/doWipe</code>) to initiate hardware-level TPM crypto-erasure of the OS drive via the Windows Recovery Environment (WinRE).
        </p>
        <div style="background: #090d16; border: 1px solid #1e293b; padding: 1rem; border-radius: 6px; margin-bottom: 1.25rem;">
          <div style="font-size: 0.8rem; color: #e2e8f0; font-weight: 600; margin-bottom: 0.25rem;">Security Governance Warning:</div>
          <div style="font-size: 0.75rem; color: #94a3b8;">
            In production environments with Dimension 6 Dual-Custody active, executing RemoteWipe requires 4-Eyes verification from two independent administrators.
          </div>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-danger" onclick="MdmCspTable.triggerRemoteWipePrompt()" style="background: #e11d48; border-color: #be123c;">
            ⚡ Trigger Native RemoteWipe CSP
          </button>
        </div>
      </div>
    `;
  },

  openNewCspModal() {
    const name = prompt('Enter CSP Policy Name:', 'Disable Windows Cortana CSP');
    if (!name) return;
    const uri = prompt('Enter OMA-DM URI (must begin with ./Vendor/MSFT/):', './Vendor/MSFT/Policy/Config/Experience/AllowCortana');
    if (!uri) return;

    window.FleetAPI.createMdmCsp({
      name,
      csp_uri: uri,
      csp_type: 'SET',
      wmi_class: 'MDM_Policy_Config01_Experience02',
      data_type: 'int',
      target_value: '0',
      target_group_id: 'grp-all'
    }).then(() => {
      alert('Native OMA-DM CSP registered successfully!');
      this.refresh();
    }).catch(err => alert('Error: ' + err.message));
  },

  inspectScript(id) {
    window.apiFetch(`/api/v1/fleet/mdm/csps/${encodeURIComponent(id)}/script`).then(res => res.text()).then(script => {
      alert(`Native PowerShell WMI Bridge Script:\n\n${script}`);
    }).catch(err => alert('Error: ' + err.message));
  },

  deleteCsp(id) {
    if (!confirm('Delete native CSP configuration?')) return;
    window.FleetAPI.deleteMdmCsp(id).then(() => {
      this.refresh();
    }).catch(err => alert('Error: ' + err.message));
  },

  copyAutopilotHash(deviceId) {
    const h = this.hashes.find(x => x.device_id === deviceId);
    if (h && h.hardware_hash_4k) {
      navigator.clipboard.writeText(h.hardware_hash_4k).then(() => {
        alert('Autopilot 4K Hardware Hash copied to clipboard! Ready for Microsoft Intune Autopilot CSV import.');
      }).catch(() => {
        alert('Hash: ' + h.hardware_hash_4k.slice(0, 100) + '...');
      });
    }
  },

  triggerRemoteWipePrompt() {
    const devId = prompt('Enter Device ID to wipe (e.g. dev-livingroom-pc):', 'dev-livingroom-pc');
    if (!devId) return;

    window.FleetAPI.dispatchNativeRemoteWipe({
      device_id: devId,
      wipe_method: 'REMOTE_WIPE_CSP',
      initiated_by: 'admin.operator@localpilot.corp'
    }).then(res => {
      alert(`Native RemoteWipe CSP dispatched!\n\nWipe ID: ${res.wipe_id}\nStatus: ${res.status}\nTarget: ${res.hostname}\n\nPowerShell Execution Payload:\n${res.native_powershell_script}`);
      this.refresh();
    }).catch(err => alert('Error: ' + err.message));
  }
};

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
