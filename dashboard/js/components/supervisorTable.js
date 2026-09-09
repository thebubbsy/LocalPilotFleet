/**
 * LocalPilot Fleet — Host Service Supervisor & Watchdog Dashboard Blade
 * dashboard/js/components/supervisorTable.js
 *
 * Dimension 1: Agent Architecture & Host Execution Model
 * Displays active Windows Service supervisor processes, external watchdog status,
 * Windows Job Object resource caps (5% CPU, 150MB RAM), and automated crash recovery forensics.
 */

window.SupervisorTable = {
  currentTab: 'supervisors',
  stats: null,
  supervisors: [],
  crashes: [],
  groups: [],
  devices: [],

  async render() {
    const container = document.getElementById('tab-supervisor');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header" style="margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h2 style="margin: 0; font-size: 1.4rem; display: flex; align-items: center; gap: 0.5rem;">
            <span>🛡️</span> Host Service Supervisor &amp; Watchdog
            <span class="badge badge-success" style="font-size: 0.75rem; padding: 2px 8px; border-radius: 9999px;">Dimension 1</span>
          </h2>
          <p class="text-muted" style="margin: 0.25rem 0 0 0; font-size: 0.85rem;">
            Dual-process supervisor/worker execution model, external watchdog health monitor, Windows Job Object resource quotas (5% CPU, 150MB RAM caps), and sub-2-second automated crash recovery.
          </p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary btn-sm" onclick="SupervisorTable.refresh()">
            <span>🔄</span> Refresh
          </button>
          <button class="btn btn-primary btn-sm" onclick="SupervisorTable.openQuotaModal()">
            <span>⚙️</span> Resource Quotas
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="kpi-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Active Supervisors</div>
          <div class="kpi-value" id="kpi-sup-running" style="font-size: 1.6rem; font-weight: 700; color: #38bdf8; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" id="kpi-sup-running-sub" style="font-size: 0.75rem; color: #64748b;">Hardened NT Service Daemons</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Mean Recovery Time</div>
          <div class="kpi-value" id="kpi-sup-recovery" style="font-size: 1.6rem; font-weight: 700; color: #10b981; margin: 0.25rem 0;">-- ms</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">SLA Budget: &le; 2000 ms</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Job Object Quotas</div>
          <div class="kpi-value" id="kpi-sup-quotas" style="font-size: 1.6rem; font-weight: 700; color: #f59e0b; margin: 0.25rem 0;">--%</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">5% CPU / 150MB RAM Enforced</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Anti-Tamper Posture</div>
          <div class="kpi-value" id="kpi-sup-tamper" style="font-size: 1.6rem; font-weight: 700; color: #a855f7; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">DACL &amp; Process Isolation Locked</div>
        </div>
      </div>

      <!-- Subtabs Navigation -->
      <div class="subtabs" style="display: flex; gap: 0.5rem; border-bottom: 1px solid var(--border-color, #334155); margin-bottom: 1rem;">
        <button class="tab-btn active" id="subtab-btn-sup-nodes" onclick="SupervisorTable.switchSubTab('supervisors')" style="background: none; border: none; padding: 0.5rem 1rem; color: #94a3b8; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 500;">
          🖥️ Host Supervisors
        </button>
        <button class="tab-btn" id="subtab-btn-sup-crashes" onclick="SupervisorTable.switchSubTab('crashes')" style="background: none; border: none; padding: 0.5rem 1rem; color: #94a3b8; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 500;">
          💥 Crash Forensics &amp; Auto-Recovery
        </button>
        <button class="tab-btn" id="subtab-btn-sup-quotas" onclick="SupervisorTable.switchSubTab('quotas')" style="background: none; border: none; padding: 0.5rem 1rem; color: #94a3b8; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 500;">
          ⚙️ Job Object Resource Policies
        </button>
      </div>

      <!-- Subtab 1: Supervisors -->
      <div id="subtab-content-sup-nodes" class="subtab-content">
        <div class="table-container" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
          <table class="data-table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
              <tr style="background: rgba(15, 23, 42, 0.6); text-align: left; border-bottom: 1px solid #334155;">
                <th style="padding: 0.75rem 1rem;">Node / Device</th>
                <th style="padding: 0.75rem 1rem;">Service Name</th>
                <th style="padding: 0.75rem 1rem;">Status</th>
                <th style="padding: 0.75rem 1rem;">PIDs (Sup/Work/Watch)</th>
                <th style="padding: 0.75rem 1rem;">CPU Cap</th>
                <th style="padding: 0.75rem 1rem;">RAM Cap</th>
                <th style="padding: 0.75rem 1rem;">Job Object</th>
                <th style="padding: 0.75rem 1rem;">Last Watchdog Ping</th>
                <th style="padding: 0.75rem 1rem;">Actions</th>
              </tr>
            </thead>
            <tbody id="sup-nodes-tbody">
              <tr><td colspan="9" style="padding: 2rem; text-align: center; color: #64748b;">Loading host supervisors...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Subtab 2: Crash Dumps -->
      <div id="subtab-content-sup-crashes" class="subtab-content" style="display: none;">
        <div class="table-container" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
          <table class="data-table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
              <tr style="background: rgba(15, 23, 42, 0.6); text-align: left; border-bottom: 1px solid #334155;">
                <th style="padding: 0.75rem 1rem;">Crash ID</th>
                <th style="padding: 0.75rem 1rem;">Node / Device</th>
                <th style="padding: 0.75rem 1rem;">Crash Type</th>
                <th style="padding: 0.75rem 1rem;">Exit Code</th>
                <th style="padding: 0.75rem 1rem;">Recovery Action</th>
                <th style="padding: 0.75rem 1rem;">Recovery Time</th>
                <th style="padding: 0.75rem 1rem;">Crashed At</th>
                <th style="padding: 0.75rem 1rem;">Details</th>
              </tr>
            </thead>
            <tbody id="sup-crashes-tbody">
              <tr><td colspan="8" style="padding: 2rem; text-align: center; color: #64748b;">Loading crash logs...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Subtab 3: Resource Quotas Policy -->
      <div id="subtab-content-sup-quotas" class="subtab-content" style="display: none;">
        <div style="max-width: 680px; background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1.5rem;">
          <h3 style="margin: 0 0 1rem 0; font-size: 1.1rem; display: flex; align-items: center; gap: 0.5rem;">
            <span>⚙️</span> Windows Job Object Resource Policy Manager
          </h3>

          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">Target Scope</label>
            <select id="quota-target" class="form-control" style="width: 100%; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px;">
              <option value="group:grp-all">🌐 All Enrolled Nodes (grp-all)</option>
              <option value="group:grp-workstations">💻 High-Performance Workstations (grp-workstations)</option>
            </select>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
            <div>
              <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">CPU Rate Limit (% of CPU)</label>
              <input type="number" id="quota-cpu" value="5" min="1" max="50" style="width: 100%; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px;" />
              <small style="color: #64748b; font-size: 0.7rem;">Default: 5% (Enterprise Intune IME Standard)</small>
            </div>
            <div>
              <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">Commit RAM Cap (MB)</label>
              <input type="number" id="quota-ram" value="150" min="50" max="1024" style="width: 100%; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px;" />
              <small style="color: #64748b; font-size: 0.7rem;">Default: 150 MB hard commit limit</small>
            </div>
          </div>

          <div style="margin-bottom: 1.5rem; display: flex; flex-direction: column; gap: 0.75rem;">
            <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: #cbd5e1; cursor: pointer;">
              <input type="checkbox" id="quota-job-object" checked style="accent-color: #38bdf8;" />
              Enforce Hard Windows Job Object Limits (AssignProcessToJobObject)
            </label>
            <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: #cbd5e1; cursor: pointer;">
              <input type="checkbox" id="quota-tamper" checked style="accent-color: #38bdf8;" />
              Enable Anti-Tamper DACL &amp; Supervisor Process Protection
            </label>
          </div>

          <button class="btn btn-primary" onclick="SupervisorTable.saveQuotas()" style="width: 100%; padding: 0.6rem; font-weight: 600;">
            💾 Apply Job Object Quotas Across Target Fleet
          </button>
        </div>
      </div>
    `;

    await this.refresh();
  },

  async refresh() {
    try {
      const [statsRes, nodesRes, crashRes, grpRes, devRes] = await Promise.all([
        window.FleetAPI.getSupervisorStats(),
        window.FleetAPI.getSupervisorNodes(),
        window.FleetAPI.getSupervisorCrashes({ limit: 50 }),
        window.FleetAPI.getGroups(),
        window.FleetAPI.getDevices()
      ]);

      this.stats = statsRes;
      this.supervisors = nodesRes.supervisors || [];
      this.crashes = crashRes.crashes || [];
      this.groups = grpRes.groups || grpRes || [];
      this.devices = devRes.devices || devRes || [];

      this.updateKpis();
      this.renderSupervisors();
      this.renderCrashes();
      this.populateTargets();
    } catch (err) {
      console.error('Failed to load supervisor stats:', err);
    }
  },

  updateKpis() {
    if (!this.stats) return;
    document.getElementById('kpi-sup-running').innerText = `${this.stats.running_supervisors || 0} / ${this.stats.total_supervisors || 0}`;
    document.getElementById('kpi-sup-running-sub').innerText = `${this.stats.total_supervisors || 0} Registered Supervisors`;

    document.getElementById('kpi-sup-recovery').innerText = `${this.stats.mean_recovery_duration_ms || 0} ms`;
    document.getElementById('kpi-sup-quotas').innerText = `${this.stats.quota_compliance_percent || 100}%`;
    document.getElementById('kpi-sup-tamper').innerText = `${this.stats.tamper_protected_count || 0} Protected`;
  },

  switchSubTab(tab) {
    this.currentTab = tab;
    ['nodes', 'crashes', 'quotas'].forEach(t => {
      const btn = document.getElementById(`subtab-btn-sup-${t}`);
      const content = document.getElementById(`subtab-content-sup-${t}`);
      if (btn && content) {
        if ((tab === 'supervisors' && t === 'nodes') || (tab === t)) {
          btn.classList.add('active');
          btn.style.color = '#38bdf8';
          btn.style.borderBottom = '2px solid #38bdf8';
          content.style.display = 'block';
        } else {
          btn.classList.remove('active');
          btn.style.color = '#94a3b8';
          btn.style.borderBottom = '2px solid transparent';
          content.style.display = 'none';
        }
      }
    });
  },

  renderSupervisors() {
    const tbody = document.getElementById('sup-nodes-tbody');
    if (!tbody) return;

    if (this.supervisors.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="padding: 2rem; text-align: center; color: #64748b;">No registered supervisors found.</td></tr>';
      return;
    }

    tbody.innerHTML = this.supervisors.map(s => {
      let statusBadge = '';
      if (s.service_status === 'RUNNING') statusBadge = '<span class="badge badge-success" style="padding: 2px 6px; font-size: 0.75rem;">RUNNING</span>';
      else if (s.service_status === 'CRASH_LOOP') statusBadge = '<span class="badge badge-danger" style="padding: 2px 6px; font-size: 0.75rem;">CRASH_LOOP</span>';
      else statusBadge = `<span class="badge badge-secondary" style="padding: 2px 6px; font-size: 0.75rem;">${s.service_status}</span>`;

      const hostLabel = s.friendly_name ? `${s.friendly_name} (${s.hostname || s.device_id})` : (s.hostname || s.device_id);
      const pids = `${s.supervisor_pid || '--'} / ${s.worker_pid || '--'} / ${s.watchdog_pid || '--'}`;
      const jobBadge = s.job_object_active
        ? '<span style="color: #10b981; font-weight: 600;">✓ Active</span>'
        : '<span style="color: #ef4444;">✗ Disabled</span>';

      return `
        <tr style="border-bottom: 1px solid #334155;">
          <td style="padding: 0.75rem 1rem; font-weight: 600;">${hostLabel}</td>
          <td style="padding: 0.75rem 1rem;"><code>${s.service_name}</code></td>
          <td style="padding: 0.75rem 1rem;">${statusBadge}</td>
          <td style="padding: 0.75rem 1rem; font-family: monospace; color: #94a3b8;">${pids}</td>
          <td style="padding: 0.75rem 1rem; font-weight: 600; color: #38bdf8;">${s.cpu_limit_percent}%</td>
          <td style="padding: 0.75rem 1rem; font-weight: 600; color: #f59e0b;">${s.ram_limit_mb} MB</td>
          <td style="padding: 0.75rem 1rem;">${jobBadge}</td>
          <td style="padding: 0.75rem 1rem; color: #94a3b8; font-size: 0.75rem;">${s.last_watchdog_ping || '--'}</td>
          <td style="padding: 0.75rem 1rem;">
            <button class="btn btn-secondary btn-sm" onclick="SupervisorTable.openDeviceQuotaModal('${s.device_id}', ${s.cpu_limit_percent}, ${s.ram_limit_mb})" style="padding: 2px 8px; font-size: 0.75rem;">
              ⚙️ Quota
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  renderCrashes() {
    const tbody = document.getElementById('sup-crashes-tbody');
    if (!tbody) return;

    if (this.crashes.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="padding: 2rem; text-align: center; color: #64748b;">No agent crash dumps recorded. Fleet is resilient.</td></tr>';
      return;
    }

    tbody.innerHTML = this.crashes.map(c => {
      const hostLabel = c.friendly_name ? `${c.friendly_name} (${c.hostname || c.device_id})` : (c.hostname || c.device_id);

      return `
        <tr style="border-bottom: 1px solid #334155;">
          <td style="padding: 0.75rem 1rem; font-family: monospace; color: #94a3b8; font-size: 0.8rem;">${c.id}</td>
          <td style="padding: 0.75rem 1rem; font-weight: 500;">${hostLabel}</td>
          <td style="padding: 0.75rem 1rem;"><span class="badge badge-warning" style="font-size: 0.75rem;">${c.crash_type}</span></td>
          <td style="padding: 0.75rem 1rem; font-family: monospace;">${c.exit_code}</td>
          <td style="padding: 0.75rem 1rem; color: #10b981; font-weight: 600;">${c.recovery_action}</td>
          <td style="padding: 0.75rem 1rem; font-weight: 600; color: #38bdf8;">${c.recovery_duration_ms} ms</td>
          <td style="padding: 0.75rem 1rem; color: #94a3b8; font-size: 0.75rem;">${c.crashed_at}</td>
          <td style="padding: 0.75rem 1rem;">
            <button class="btn btn-secondary btn-sm" onclick="alert('Exception: ' + ${JSON.stringify(c.exception_message)} + '\\n\\nStack Trace:\\n' + ${JSON.stringify(c.stack_trace)})" style="padding: 2px 8px; font-size: 0.75rem;">
              🔍 Details
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  populateTargets() {
    const sel = document.getElementById('quota-target');
    if (!sel) return;

    let html = '';
    if (this.groups.length > 0) {
      html += '<optgroup label="Dynamic Device Groups">';
      for (const g of this.groups) {
        html += `<option value="group:${g.id}">👥 ${g.name}</option>`;
      }
      html += '</optgroup>';
    }
    if (this.devices.length > 0) {
      html += '<optgroup label="Individual Enrolled Nodes">';
      for (const d of this.devices) {
        html += `<option value="node:${d.id}">💻 ${d.friendly_name || d.hostname}</option>`;
      }
      html += '</optgroup>';
    }
    sel.innerHTML = html;
  },

  openQuotaModal() {
    this.switchSubTab('quotas');
  },

  openDeviceQuotaModal(deviceId, cpu, ram) {
    this.switchSubTab('quotas');
    const sel = document.getElementById('quota-target');
    if (sel) sel.value = `node:${deviceId}`;
    const cpuInput = document.getElementById('quota-cpu');
    if (cpuInput) cpuInput.value = cpu;
    const ramInput = document.getElementById('quota-ram');
    if (ramInput) ramInput.value = ram;
  },

  async saveQuotas() {
    const targetVal = document.getElementById('quota-target').value;
    const cpu = Number(document.getElementById('quota-cpu').value);
    const ram = Number(document.getElementById('quota-ram').value);
    const jobActive = document.getElementById('quota-job-object').checked ? 1 : 0;
    const tamperActive = document.getElementById('quota-tamper').checked ? 1 : 0;

    const isGroup = targetVal.startsWith('group:');
    const targetId = targetVal.split(':')[1];

    try {
      const payload = {
        cpu_limit_percent: cpu,
        ram_limit_mb: ram,
        job_object_active: jobActive,
        tamper_protection_enabled: tamperActive
      };
      if (isGroup) {
        payload.group_id = targetId;
      } else {
        payload.device_id = targetId;
      }

      await window.FleetAPI.updateSupervisorQuotas(payload);
      alert(`✅ Resource quotas successfully applied!\nCPU Cap: ${cpu}% | RAM Cap: ${ram}MB`);
      await this.refresh();
      this.switchSubTab('supervisors');
    } catch (err) {
      alert(`Failed to update quotas: ${err.message}`);
    }
  }
};
