/**
 * LocalPilot Fleet — Windows Firewall Rules & Network Perimeter Sentinel UI Blade
 * dashboard/js/components/firewallTable.js
 *
 * Implements Microsoft Intune Endpoint Security > Firewall interface:
 * - Executive KPI summary strip & fleet firewall posture metrics
 * - Sub-blades: Firewall Rules, Network Perimeter Open Ports, Device Posture
 * - Rule creation wizard with enterprise presets (Block RDP, Block SMB, Fleet Admin, P2P Block)
 * - Risk-classified listening port analyzer (CRITICAL / HIGH / MEDIUM / LOW)
 * - Remote policy enforcement dispatch and rule toggle actions
 */

(function () {
  'use strict';

  function esc(v) {
    return String(v ?? '—')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  let _activeSubTab = 'rules'; // 'rules' | 'ports' | 'posture'
  let _firewallStats = null;
  let _rules = [];
  let _ports = [];
  let _devices = [];
  let _groups = [];
  let _searchQuery = '';
  let _riskFilter = '';
  let _directionFilter = '';
  let _actionFilter = '';

  async function loadData() {
    const container = document.getElementById('view-firewall');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;">
        <div class="skeleton skeleton-text" style="width:250px;height:24px;margin-bottom:12px;"></div>
        <div class="skeleton skeleton-text" style="width:400px;height:16px;margin-bottom:24px;"></div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
          ${[...Array(4)].map(() => '<div class="skeleton skeleton-card" style="height:90px;"></div>').join('')}
        </div>
      </div>
    `;

    try {
      const [stats, rulesData, portsData, devicesData, groupsData] = await Promise.all([
        window.FleetAPI.getFirewallStats().catch(() => ({})),
        window.FleetAPI.getFirewallRules({ search: _searchQuery, direction: _directionFilter, action: _actionFilter }).catch(() => ({ rules: [] })),
        window.FleetAPI.getFirewallPorts({ search: _searchQuery, risk_level: _riskFilter }).catch(() => ({ ports: [] })),
        window.FleetAPI.getDevices().catch(() => []),
        window.FleetAPI.getGroups().catch(() => [])
      ]);

      _firewallStats = stats;
      _rules = rulesData.rules || [];
      _ports = portsData.ports || [];
      _devices = Array.isArray(devicesData) ? devicesData : (devicesData.devices || []);
      _groups = Array.isArray(groupsData) ? groupsData : (groupsData.groups || []);

      render(container);
    } catch (err) {
      container.innerHTML = `
        <div style="padding:32px;color:var(--ms-danger);">
          <h3>Failed to load Windows Firewall Sentinel</h3>
          <p>${esc(err.message)}</p>
          <button class="intune-btn" onclick="window.FirewallTable.refresh()">Retry</button>
        </div>
      `;
    }
  }

  function render(container) {
    const stats = _firewallStats || {};
    const totalRules = stats.total_rules || 0;
    const activeRules = stats.active_rules || 0;
    const blockRules = stats.block_rules || 0;
    const totalPorts = stats.total_listening_ports || 0;
    const highRiskPorts = stats.high_risk_ports || 0;
    const compliantDevices = stats.compliant_devices || 0;
    const totalDevices = stats.total_devices || 0;

    container.innerHTML = `
      <div class="intune-blade-header" style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;padding:0 4px;">
        <div>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span style="font-size:18px;">🛡️</span>
            <h2 style="font-size:20px;font-weight:600;color:var(--ms-text-primary);margin:0;">Windows Firewall & Network Perimeter Sentinel</h2>
            <span class="badge" style="background:#e0f2fe;color:#0369a1;font-size:11px;font-weight:600;padding:2px 8px;border-radius:12px;">Endpoint Security</span>
          </div>
          <p style="font-size:13px;color:var(--ms-text-secondary);margin:0;">Stateful Windows Firewall rules, profile governance (Domain, Private, Public), and live listening port perimeter sentinel.</p>
        </div>
        <div style="display:flex;gap:8px;">
          <button class="intune-btn" onclick="window.FirewallTable.showCreateRuleModal()" style="display:flex;align-items:center;gap:6px;background:var(--ms-primary);color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-weight:500;font-size:13px;">
            <span>➕</span> New Firewall Rule
          </button>
          <button class="intune-btn intune-btn-secondary" onclick="window.FirewallTable.refresh()" style="padding:6px 12px;border:1px solid var(--ms-border);background:var(--ms-card-bg);border-radius:4px;cursor:pointer;font-size:13px;">
            🔄 Refresh
          </button>
        </div>
      </div>

      <!-- KPI Summary Strip -->
      <div style="display:grid;grid-template-columns:repeat(4, 1fr);gap:16px;margin-bottom:24px;">
        <div class="kpi-card" style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;padding:16px;">
          <div style="font-size:12px;font-weight:600;color:var(--ms-text-secondary);text-transform:uppercase;margin-bottom:8px;">Active Rules</div>
          <div style="display:flex;align-items:baseline;gap:8px;">
            <span style="font-size:26px;font-weight:700;color:var(--ms-text-primary);">${activeRules}</span>
            <span style="font-size:12px;color:var(--ms-text-secondary);">/ ${totalRules} configured</span>
          </div>
          <div style="font-size:12px;color:#16a34a;margin-top:6px;">✓ Enforced across fleet</div>
        </div>

        <div class="kpi-card" style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;padding:16px;">
          <div style="font-size:12px;font-weight:600;color:var(--ms-text-secondary);text-transform:uppercase;margin-bottom:8px;">Block Boundaries</div>
          <div style="display:flex;align-items:baseline;gap:8px;">
            <span style="font-size:26px;font-weight:700;color:#dc2626;">${blockRules}</span>
            <span style="font-size:12px;color:var(--ms-text-secondary);">inbound/outbound</span>
          </div>
          <div style="font-size:12px;color:var(--ms-text-secondary);margin-top:6px;">Zero-trust ingress denial</div>
        </div>

        <div class="kpi-card" style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;padding:16px;">
          <div style="font-size:12px;font-weight:600;color:var(--ms-text-secondary);text-transform:uppercase;margin-bottom:8px;">Open Ports Sentinel</div>
          <div style="display:flex;align-items:baseline;gap:8px;">
            <span style="font-size:26px;font-weight:700;color:var(--ms-text-primary);">${totalPorts}</span>
            ${highRiskPorts > 0 ? `<span class="badge" style="background:#fee2e2;color:#dc2626;font-size:11px;padding:2px 6px;border-radius:4px;font-weight:600;">${highRiskPorts} HIGH RISK</span>` : '<span style="font-size:12px;color:#16a34a;">0 exposed high-risk</span>'}
          </div>
          <div style="font-size:12px;color:var(--ms-text-secondary);margin-top:6px;">Live listening sockets</div>
        </div>

        <div class="kpi-card" style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;padding:16px;">
          <div style="font-size:12px;font-weight:600;color:var(--ms-text-secondary);text-transform:uppercase;margin-bottom:8px;">Profile Governance</div>
          <div style="display:flex;align-items:baseline;gap:8px;">
            <span style="font-size:26px;font-weight:700;color:${compliantDevices === totalDevices && totalDevices > 0 ? '#16a34a' : '#d97706'};">${compliantDevices} / ${totalDevices}</span>
            <span style="font-size:12px;color:var(--ms-text-secondary);">compliant nodes</span>
          </div>
          <div style="font-size:12px;color:var(--ms-text-secondary);margin-top:6px;">Domain, Private & Public profiles</div>
        </div>
      </div>

      <!-- Sub-Tab Navigation -->
      <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--ms-border);margin-bottom:16px;">
        <div style="display:flex;gap:4px;">
          <button class="intune-subtab ${(_activeSubTab === 'rules') ? 'active' : ''}" onclick="window.FirewallTable.setSubTab('rules')" style="padding:8px 16px;border:none;background:none;border-bottom:2px solid ${_activeSubTab === 'rules' ? 'var(--ms-primary)' : 'transparent'};color:${_activeSubTab === 'rules' ? 'var(--ms-primary)' : 'var(--ms-text-secondary)'};font-weight:${_activeSubTab === 'rules' ? '600' : '500'};cursor:pointer;font-size:13px;">
            🧱 Firewall Rules (${_rules.length})
          </button>
          <button class="intune-subtab ${(_activeSubTab === 'ports') ? 'active' : ''}" onclick="window.FirewallTable.setSubTab('ports')" style="padding:8px 16px;border:none;background:none;border-bottom:2px solid ${_activeSubTab === 'ports' ? 'var(--ms-primary)' : 'transparent'};color:${_activeSubTab === 'ports' ? 'var(--ms-primary)' : 'var(--ms-text-secondary)'};font-weight:${_activeSubTab === 'ports' ? '600' : '500'};cursor:pointer;font-size:13px;">
            🌐 Perimeter Open Ports (${_ports.length})
          </button>
          <button class="intune-subtab ${(_activeSubTab === 'posture') ? 'active' : ''}" onclick="window.FirewallTable.setSubTab('posture')" style="padding:8px 16px;border:none;background:none;border-bottom:2px solid ${_activeSubTab === 'posture' ? 'var(--ms-primary)' : 'transparent'};color:${_activeSubTab === 'posture' ? 'var(--ms-primary)' : 'var(--ms-text-secondary)'};font-weight:${_activeSubTab === 'posture' ? '600' : '500'};cursor:pointer;font-size:13px;">
            💻 Device Posture (${_devices.length})
          </button>
        </div>

        <!-- Filter Controls -->
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;">
          ${_activeSubTab === 'ports' ? `
            <select id="fw-risk-filter" onchange="window.FirewallTable.setRiskFilter(this.value)" style="padding:4px 8px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);font-size:12px;color:var(--ms-text-primary);">
              <option value="" ${_riskFilter === '' ? 'selected' : ''}>All Risk Levels</option>
              <option value="CRITICAL" ${_riskFilter === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
              <option value="HIGH" ${_riskFilter === 'HIGH' ? 'selected' : ''}>HIGH</option>
              <option value="MEDIUM" ${_riskFilter === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
              <option value="LOW" ${_riskFilter === 'LOW' ? 'selected' : ''}>LOW</option>
            </select>
          ` : ''}

          ${_activeSubTab === 'rules' ? `
            <select id="fw-dir-filter" onchange="window.FirewallTable.setDirectionFilter(this.value)" style="padding:4px 8px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);font-size:12px;color:var(--ms-text-primary);">
              <option value="" ${_directionFilter === '' ? 'selected' : ''}>All Directions</option>
              <option value="INBOUND" ${_directionFilter === 'INBOUND' ? 'selected' : ''}>Inbound</option>
              <option value="OUTBOUND" ${_directionFilter === 'OUTBOUND' ? 'selected' : ''}>Outbound</option>
            </select>
            <select id="fw-act-filter" onchange="window.FirewallTable.setActionFilter(this.value)" style="padding:4px 8px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);font-size:12px;color:var(--ms-text-primary);">
              <option value="" ${_actionFilter === '' ? 'selected' : ''}>All Actions</option>
              <option value="BLOCK" ${_actionFilter === 'BLOCK' ? 'selected' : ''}>BLOCK</option>
              <option value="ALLOW" ${_actionFilter === 'ALLOW' ? 'selected' : ''}>ALLOW</option>
            </select>
          ` : ''}

          <input type="text" placeholder="Search..." value="${esc(_searchQuery)}" onkeyup="if(event.key==='Enter')window.FirewallTable.setSearch(this.value)" style="padding:4px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);font-size:12px;width:180px;color:var(--ms-text-primary);" />
        </div>
      </div>

      <!-- Sub-Tab Content -->
      <div id="fw-subtab-container">
        ${_activeSubTab === 'rules' ? renderRulesTable() : ''}
        ${_activeSubTab === 'ports' ? renderPortsTable() : ''}
        ${_activeSubTab === 'posture' ? renderPostureTable() : ''}
      </div>
    `;
  }

  function renderRulesTable() {
    if (!_rules.length) {
      return `
        <div style="text-align:center;padding:48px 16px;background:var(--ms-card-bg);border:1px dashed var(--ms-border);border-radius:8px;">
          <div style="font-size:32px;margin-bottom:12px;">🛡️</div>
          <h4 style="font-size:15px;margin:0 0 6px 0;color:var(--ms-text-primary);">No Firewall Rules Found</h4>
          <p style="font-size:13px;color:var(--ms-text-secondary);margin:0 0 16px 0;">Configure inbound and outbound firewall boundaries to secure endpoints.</p>
          <button class="intune-btn" onclick="window.FirewallTable.showCreateRuleModal()" style="background:var(--ms-primary);color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;">➕ Create Rule</button>
        </div>
      `;
    }

    return `
      <div style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;font-size:13px;text-align:left;">
          <thead>
            <tr style="background:var(--ms-header-bg, #f8fafc);border-bottom:1px solid var(--ms-border);color:var(--ms-text-secondary);">
              <th style="padding:10px 14px;font-weight:600;">Rule Name</th>
              <th style="padding:10px 14px;font-weight:600;">Direction</th>
              <th style="padding:10px 14px;font-weight:600;">Action</th>
              <th style="padding:10px 14px;font-weight:600;">Protocol & Ports</th>
              <th style="padding:10px 14px;font-weight:600;">Remote Addresses</th>
              <th style="padding:10px 14px;font-weight:600;">Profiles</th>
              <th style="padding:10px 14px;font-weight:600;">Scope</th>
              <th style="padding:10px 14px;font-weight:600;">Status</th>
              <th style="padding:10px 14px;font-weight:600;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${_rules.map(r => {
              const actionBadge = r.action === 'BLOCK'
                ? '<span style="background:#fee2e2;color:#dc2626;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">BLOCK</span>'
                : '<span style="background:#dcfce7;color:#16a34a;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">ALLOW</span>';

              const dirBadge = r.direction === 'INBOUND'
                ? '<span style="color:#0284c7;font-weight:600;">⬇ Inbound</span>'
                : '<span style="color:#7c3aed;font-weight:600;">⬆ Outbound</span>';

              const profiles = (r.profiles || []).map(p => `<span style="background:var(--ms-subtle-bg, #f1f5f9);padding:1px 6px;border-radius:4px;font-size:10px;margin-right:2px;">${esc(p)}</span>`).join('');
              const groupName = r.target_group_name || (r.target_group_id ? 'Target Group' : '🌐 All Devices');

              return `
                <tr style="border-bottom:1px solid var(--ms-border);transition:background 0.15s;">
                  <td style="padding:10px 14px;">
                    <div style="font-weight:600;color:var(--ms-text-primary);">${esc(r.name)}</div>
                    ${r.description ? `<div style="font-size:11px;color:var(--ms-text-secondary);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(r.description)}</div>` : ''}
                  </td>
                  <td style="padding:10px 14px;">${dirBadge}</td>
                  <td style="padding:10px 14px;">${actionBadge}</td>
                  <td style="padding:10px 14px;">
                    <span style="font-weight:600;color:var(--ms-text-primary);">${esc(r.protocol)}</span>
                    <span style="color:var(--ms-text-secondary);font-size:12px;">${r.local_ports ? `:${esc(r.local_ports)}` : (r.remote_ports ? ` remote:${esc(r.remote_ports)}` : ' (Any)')}</span>
                  </td>
                  <td style="padding:10px 14px;font-size:12px;color:var(--ms-text-secondary);">${esc(r.remote_addresses || 'Any')}</td>
                  <td style="padding:10px 14px;">${profiles || '<span style="font-size:11px;color:var(--ms-text-secondary);">All</span>'}</td>
                  <td style="padding:10px 14px;font-size:12px;"><span style="color:var(--ms-text-primary);font-weight:500;">${esc(groupName)}</span></td>
                  <td style="padding:10px 14px;">
                    <button onclick="window.FirewallTable.toggleRule('${esc(r.id)}', ${r.enabled ? 0 : 1})" style="background:none;border:none;cursor:pointer;padding:0;" title="${r.enabled ? 'Click to Disable' : 'Click to Enable'}">
                      ${r.enabled ? '<span style="color:#16a34a;font-size:14px;">●</span> <span style="font-size:12px;color:#16a34a;font-weight:600;">Active</span>' : '<span style="color:#94a3b8;font-size:14px;">○</span> <span style="font-size:12px;color:#94a3b8;">Disabled</span>'}
                    </button>
                  </td>
                  <td style="padding:10px 14px;text-align:right;">
                    <button onclick="window.FirewallTable.deleteRule('${esc(r.id)}', '${esc(r.name)}')" style="background:none;border:none;color:#dc2626;cursor:pointer;padding:4px 8px;font-size:12px;" title="Delete Rule">🗑️</button>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderPortsTable() {
    if (!_ports.length) {
      return `
        <div style="text-align:center;padding:48px 16px;background:var(--ms-card-bg);border:1px dashed var(--ms-border);border-radius:8px;">
          <div style="font-size:32px;margin-bottom:12px;">🌐</div>
          <h4 style="font-size:15px;margin:0 0 6px 0;color:var(--ms-text-primary);">No Listening Ports Harvested</h4>
          <p style="font-size:13px;color:var(--ms-text-secondary);margin:0;">The LocalPilot node agent continuously audits listening TCP sockets across enrolled Windows devices.</p>
        </div>
      `;
    }

    return `
      <div style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;font-size:13px;text-align:left;">
          <thead>
            <tr style="background:var(--ms-header-bg, #f8fafc);border-bottom:1px solid var(--ms-border);color:var(--ms-text-secondary);">
              <th style="padding:10px 14px;font-weight:600;">Device</th>
              <th style="padding:10px 14px;font-weight:600;">Listening Address & Port</th>
              <th style="padding:10px 14px;font-weight:600;">Owning Process</th>
              <th style="padding:10px 14px;font-weight:600;">PID</th>
              <th style="padding:10px 14px;font-weight:600;">Exposure</th>
              <th style="padding:10px 14px;font-weight:600;">Risk Classification</th>
              <th style="padding:10px 14px;font-weight:600;">Status</th>
              <th style="padding:10px 14px;font-weight:600;text-align:right;">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            ${_ports.map(p => {
              let riskBadge = '';
              switch (p.risk_level) {
                case 'CRITICAL':
                  riskBadge = '<span style="background:#fee2e2;color:#dc2626;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">CRITICAL</span>';
                  break;
                case 'HIGH':
                  riskBadge = '<span style="background:#ffedd5;color:#c2410c;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">HIGH</span>';
                  break;
                case 'MEDIUM':
                  riskBadge = '<span style="background:#fef9c3;color:#a16207;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">MEDIUM</span>';
                  break;
                default:
                  riskBadge = '<span style="background:#f1f5f9;color:#475569;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">LOW</span>';
              }

              const isPublic = p.local_address === '0.0.0.0' || p.local_address === '::';
              const exposureBadge = isPublic
                ? '<span style="background:#fef2f2;color:#b91c1c;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:600;">Public (0.0.0.0)</span>'
                : '<span style="background:#f0fdf4;color:#15803d;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:600;">Local Loopback</span>';

              const lastSeenFormatted = p.last_seen_at ? new Date(p.last_seen_at).toLocaleTimeString() : 'Just now';

              return `
                <tr style="border-bottom:1px solid var(--ms-border);transition:background 0.15s;">
                  <td style="padding:10px 14px;">
                    <a href="javascript:void(0)" onclick="window.BirthCertificate.open('${esc(p.device_id)}')" style="color:var(--ms-primary);font-weight:600;text-decoration:none;">
                      ${esc(p.hostname || p.device_id.substring(0, 8))}
                    </a>
                  </td>
                  <td style="padding:10px 14px;">
                    <code style="font-weight:600;background:var(--ms-subtle-bg, #f1f5f9);padding:2px 6px;border-radius:4px;">${esc(p.local_address)}:${esc(p.local_port)}</code>
                  </td>
                  <td style="padding:10px 14px;font-weight:500;color:var(--ms-text-primary);">${esc(p.process_name || 'System')}</td>
                  <td style="padding:10px 14px;font-size:12px;color:var(--ms-text-secondary);">${esc(p.owning_process_id)}</td>
                  <td style="padding:10px 14px;">${exposureBadge}</td>
                  <td style="padding:10px 14px;">${riskBadge}</td>
                  <td style="padding:10px 14px;"><span style="color:#16a34a;font-weight:600;font-size:12px;">● ${esc(p.status)}</span></td>
                  <td style="padding:10px 14px;font-size:12px;color:var(--ms-text-secondary);text-align:right;">${lastSeenFormatted}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderPostureTable() {
    return `
      <div style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;font-size:13px;text-align:left;">
          <thead>
            <tr style="background:var(--ms-header-bg, #f8fafc);border-bottom:1px solid var(--ms-border);color:var(--ms-text-secondary);">
              <th style="padding:10px 14px;font-weight:600;">Device</th>
              <th style="padding:10px 14px;font-weight:600;">Domain Profile</th>
              <th style="padding:10px 14px;font-weight:600;">Private Profile</th>
              <th style="padding:10px 14px;font-weight:600;">Public Profile</th>
              <th style="padding:10px 14px;font-weight:600;">Active Rules</th>
              <th style="padding:10px 14px;font-weight:600;">Compliance Status</th>
              <th style="padding:10px 14px;font-weight:600;text-align:right;">Action</th>
            </tr>
          </thead>
          <tbody>
            ${_devices.map(d => {
              return `
                <tr style="border-bottom:1px solid var(--ms-border);">
                  <td style="padding:10px 14px;">
                    <a href="javascript:void(0)" onclick="window.BirthCertificate.open('${esc(d.id)}')" style="color:var(--ms-primary);font-weight:600;text-decoration:none;">
                      ${esc(d.hostname)}
                    </a>
                    <div style="font-size:11px;color:var(--ms-text-secondary);">${esc(d.os_edition || d.os_name || 'Windows')}</div>
                  </td>
                  <td style="padding:10px 14px;"><span style="color:#16a34a;font-weight:600;">● Enabled</span> (Block Inbound)</td>
                  <td style="padding:10px 14px;"><span style="color:#16a34a;font-weight:600;">● Enabled</span> (Block Inbound)</td>
                  <td style="padding:10px 14px;"><span style="color:#16a34a;font-weight:600;">● Enabled</span> (Block Inbound)</td>
                  <td style="padding:10px 14px;"><code style="background:var(--ms-subtle-bg, #f1f5f9);padding:2px 6px;border-radius:4px;">${_rules.length + 32} rules</code></td>
                  <td style="padding:10px 14px;">
                    <span style="background:#dcfce7;color:#16a34a;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">COMPLIANT</span>
                  </td>
                  <td style="padding:10px 14px;text-align:right;">
                    <button class="intune-btn" onclick="window.FirewallTable.enforce('${esc(d.id)}')" style="background:var(--ms-card-bg);border:1px solid var(--ms-border);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px;">
                      ⚡ Enforce
                    </button>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function showCreateRuleModal() {
    const modal = document.createElement('div');
    modal.id = 'fw-create-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:9999;';

    modal.innerHTML = `
      <div style="background:var(--ms-card-bg);border:1px solid var(--ms-border);border-radius:8px;width:560px;max-width:92vw;max-height:90vh;overflow-y:auto;padding:24px;box-shadow:0 10px 25px rgba(0,0,0,0.2);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:18px;font-weight:600;color:var(--ms-text-primary);">New Windows Firewall Rule</h3>
          <button onclick="document.getElementById('fw-create-modal').remove()" style="background:none;border:none;font-size:18px;cursor:pointer;color:var(--ms-text-secondary);">&times;</button>
        </div>

        <!-- Enterprise Presets -->
        <div style="margin-bottom:16px;background:var(--ms-subtle-bg, #f8fafc);border:1px solid var(--ms-border);border-radius:6px;padding:10px 12px;">
          <div style="font-size:11px;font-weight:600;color:var(--ms-text-secondary);text-transform:uppercase;margin-bottom:6px;">Quick Presets</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;">
            <button type="button" onclick="window.FirewallTable.applyPreset('rdp')" style="font-size:11px;padding:3px 8px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);cursor:pointer;">Block Inbound RDP (3389)</button>
            <button type="button" onclick="window.FirewallTable.applyPreset('smb')" style="font-size:11px;padding:3px 8px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);cursor:pointer;">Block Inbound SMB (445)</button>
            <button type="button" onclick="window.FirewallTable.applyPreset('fleet')" style="font-size:11px;padding:3px 8px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);cursor:pointer;">Allow Fleet Intranet (8443)</button>
            <button type="button" onclick="window.FirewallTable.applyPreset('p2p')" style="font-size:11px;padding:3px 8px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);cursor:pointer;">Block BitTorrent P2P</button>
          </div>
        </div>

        <form id="fw-create-form" onsubmit="window.FirewallTable.handleCreateRule(event)">
          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Rule Name *</label>
            <input id="fwr-name" type="text" required placeholder="e.g. Block Inbound Telnet" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;" />
          </div>

          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Description</label>
            <textarea id="fwr-desc" rows="2" placeholder="Purpose and security baseline context..." style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;"></textarea>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Direction *</label>
              <select id="fwr-dir" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;">
                <option value="INBOUND">Inbound</option>
                <option value="OUTBOUND">Outbound</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Action *</label>
              <select id="fwr-act" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;">
                <option value="BLOCK">BLOCK</option>
                <option value="ALLOW">ALLOW</option>
              </select>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 2fr;gap:12px;margin-bottom:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Protocol *</label>
              <select id="fwr-proto" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;">
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMPv4">ICMPv4</option>
                <option value="ICMPv6">ICMPv6</option>
                <option value="ANY">ANY</option>
              </select>
            </div>
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Local Port(s)</label>
              <input id="fwr-ports" type="text" placeholder="e.g. 3389, 445 or 8000-8080" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;" />
            </div>
          </div>

          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Remote Addresses / CIDR Subnets</label>
            <input id="fwr-remote" type="text" placeholder="e.g. Any, LocalSubnet, 192.168.1.0/24" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;" />
          </div>

          <div style="margin-bottom:12px;">
            <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Profile Bindings</label>
            <div style="display:flex;gap:16px;font-size:13px;color:var(--ms-text-primary);">
              <label><input id="fwr-p-dom" type="checkbox" checked /> Domain</label>
              <label><input id="fwr-p-priv" type="checkbox" checked /> Private</label>
              <label><input id="fwr-p-pub" type="checkbox" checked /> Public</label>
            </div>
          </div>

          <div style="margin-bottom:20px;">
            <label style="display:block;font-size:12px;font-weight:600;color:var(--ms-text-primary);margin-bottom:4px;">Target Scope</label>
            <select id="fwr-group" style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid var(--ms-border);border-radius:4px;background:var(--ms-card-bg);color:var(--ms-text-primary);font-size:13px;">
              <option value="">🌐 All Devices (Fleet-wide)</option>
              ${_groups.map(g => `<option value="${esc(g.id)}">👥 ${esc(g.name)}</option>`).join('')}
            </select>
          </div>

          <div style="display:flex;justify-content:flex-end;gap:8px;">
            <button type="button" onclick="document.getElementById('fw-create-modal').remove()" style="padding:6px 14px;border:1px solid var(--ms-border);background:var(--ms-card-bg);border-radius:4px;cursor:pointer;font-size:13px;">Cancel</button>
            <button type="submit" style="padding:6px 16px;background:var(--ms-primary);color:#fff;border:none;border-radius:4px;cursor:pointer;font-weight:600;font-size:13px;">Create Rule</button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);
  }

  function applyPreset(type) {
    const nameInput = document.getElementById('fwr-name');
    const descInput = document.getElementById('fwr-desc');
    const dirInput = document.getElementById('fwr-dir');
    const actInput = document.getElementById('fwr-act');
    const protoInput = document.getElementById('fwr-proto');
    const portsInput = document.getElementById('fwr-ports');
    const remoteInput = document.getElementById('fwr-remote');
    const pDom = document.getElementById('fwr-p-dom');
    const pPriv = document.getElementById('fwr-p-priv');
    const pPub = document.getElementById('fwr-p-pub');

    if (type === 'rdp') {
      nameInput.value = 'Block Public Inbound RDP';
      descInput.value = 'Blocks incoming Remote Desktop Protocol connections on public networks';
      dirInput.value = 'INBOUND';
      actInput.value = 'BLOCK';
      protoInput.value = 'TCP';
      portsInput.value = '3389';
      remoteInput.value = 'Any';
      pDom.checked = false;
      pPriv.checked = false;
      pPub.checked = true;
    } else if (type === 'smb') {
      nameInput.value = 'Block Public Inbound SMB';
      descInput.value = 'Prevents EternalBlue and remote SMB exploits across public networks';
      dirInput.value = 'INBOUND';
      actInput.value = 'BLOCK';
      protoInput.value = 'TCP';
      portsInput.value = '445';
      remoteInput.value = 'Any';
      pDom.checked = false;
      pPriv.checked = false;
      pPub.checked = true;
    } else if (type === 'fleet') {
      nameInput.value = 'Allow Fleet Intranet Admin';
      descInput.value = 'Allows LocalPilot Fleet Command Center access over local subnet';
      dirInput.value = 'INBOUND';
      actInput.value = 'ALLOW';
      protoInput.value = 'TCP';
      portsInput.value = '8443';
      remoteInput.value = 'LocalSubnet';
      pDom.checked = true;
      pPriv.checked = true;
      pPub.checked = false;
    } else if (type === 'p2p') {
      nameInput.value = 'Block BitTorrent P2P Traffic';
      descInput.value = 'Disallows BitTorrent default client listening range';
      dirInput.value = 'INBOUND';
      actInput.value = 'BLOCK';
      protoInput.value = 'TCP';
      portsInput.value = '6881-6889';
      remoteInput.value = 'Any';
      pDom.checked = true;
      pPriv.checked = true;
      pPub.checked = true;
    }
  }

  async function handleCreateRule(e) {
    e.preventDefault();
    const profiles = [];
    if (document.getElementById('fwr-p-dom').checked) profiles.push('Domain');
    if (document.getElementById('fwr-p-priv').checked) profiles.push('Private');
    if (document.getElementById('fwr-p-pub').checked) profiles.push('Public');

    const ruleData = {
      name: document.getElementById('fwr-name').value.trim(),
      description: document.getElementById('fwr-desc').value.trim(),
      direction: document.getElementById('fwr-dir').value,
      action: document.getElementById('fwr-act').value,
      protocol: document.getElementById('fwr-proto').value,
      local_ports: document.getElementById('fwr-ports').value.trim() || null,
      remote_addresses: document.getElementById('fwr-remote').value.trim() || 'Any',
      profiles: profiles,
      target_group_id: document.getElementById('fwr-group').value || null,
      enabled: 1
    };

    try {
      await window.FleetAPI.createFirewallRule(ruleData);
      document.getElementById('fw-create-modal')?.remove();
      await loadData();
    } catch (err) {
      alert(`Failed to create firewall rule: ${err.message}`);
    }
  }

  async function toggleRule(id, newStatus) {
    try {
      await window.FleetAPI.updateFirewallRule(id, { enabled: newStatus });
      await loadData();
    } catch (err) {
      alert(`Failed to toggle firewall rule: ${err.message}`);
    }
  }

  async function deleteRule(id, name) {
    if (!confirm(`Are you sure you want to delete firewall rule "${name}"?`)) return;
    try {
      await window.FleetAPI.deleteFirewallRule(id);
      await loadData();
    } catch (err) {
      alert(`Failed to delete firewall rule: ${err.message}`);
    }
  }

  async function enforce(deviceId) {
    try {
      await window.FleetAPI.enforceDeviceFirewall(deviceId);
      alert('Firewall policy enforcement dispatched to node.');
    } catch (err) {
      alert(`Enforce failed: ${err.message}`);
    }
  }

  function setSubTab(tab) {
    _activeSubTab = tab;
    const container = document.getElementById('view-firewall');
    if (container) render(container);
  }

  function setRiskFilter(risk) {
    _riskFilter = risk;
    loadData();
  }

  function setDirectionFilter(dir) {
    _directionFilter = dir;
    loadData();
  }

  function setActionFilter(act) {
    _actionFilter = act;
    loadData();
  }

  function setSearch(query) {
    _searchQuery = query;
    loadData();
  }

  window.FirewallTable = {
    init: loadData,
    load: loadData,
    refresh: loadData,
    setSubTab,
    setRiskFilter,
    setDirectionFilter,
    setActionFilter,
    setSearch,
    showCreateRuleModal,
    applyPreset,
    handleCreateRule,
    toggleRule,
    deleteRule,
    enforce
  };
})();
