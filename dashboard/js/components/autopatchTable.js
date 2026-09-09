/**
 * LocalPilot Fleet — Windows Autopatch & Automated Patch Release Cadence Blade
 * dashboard/js/components/autopatchTable.js
 */

(function () {
  'use strict';

  let currentSubTab = 'releases'; // 'releases' | 'deployments' | 'rings'
  let cachedStats = null;
  let cachedReleases = [];
  let cachedRings = [];
  let cachedDeployments = [];
  let filterReleaseType = '';
  let searchQuery = '';

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getPhaseBadge(phase) {
    const p = String(phase || 'TEST').toUpperCase();
    if (p === 'TEST') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3b82f6;font-weight:700;border:1px solid #3b82f644;">🧪 TEST (CANARY)</span>';
    } else if (p === 'FIRST') {
      return '<span class="badge" style="background:rgba(139,92,246,0.15);color:#8b5cf6;font-weight:700;border:1px solid #8b5cf644;">🚀 FIRST (1%)</span>';
    } else if (p === 'FAST') {
      return '<span class="badge" style="background:rgba(245,158,11,0.15);color:#f59e0b;font-weight:700;border:1px solid #f59e0b44;">⚡ FAST (9%)</span>';
    } else if (p === 'BROAD') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;font-weight:700;border:1px solid #10b98144;">🌐 BROAD (90%)</span>';
    } else if (p === 'COMPLETED') {
      return '<span class="badge" style="background:rgba(16,185,129,0.25);color:#10b981;font-weight:800;border:1px solid #10b98188;">✅ COMPLETED</span>';
    } else if (p === 'ROLLED_BACK') {
      return '<span class="badge" style="background:rgba(239,68,68,0.25);color:#ef4444;font-weight:800;border:1px solid #ef444488;animation:pulse 2s infinite;">🛑 ROLLED BACK</span>';
    }
    return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#9ca3af;">⏸️ ' + esc(p) + '</span>';
  }

  function getStatusBadge(status) {
    const s = String(status || 'PENDING').toUpperCase();
    if (s === 'INSTALLED') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;font-weight:600;">✅ INSTALLED</span>';
    } else if (s === 'INSTALLING' || s === 'DOWNLOADING') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3b82f6;font-weight:600;">⏳ ' + esc(s) + '</span>';
    } else if (s === 'REBOOT_PENDING') {
      return '<span class="badge" style="background:rgba(245,158,11,0.2);color:#f59e0b;font-weight:600;">🔄 REBOOT PENDING</span>';
    } else if (s === 'FAILED') {
      return '<span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-weight:700;">❌ FAILED</span>';
    } else if (s === 'ROLLED_BACK') {
      return '<span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-weight:600;">↩️ ROLLED BACK</span>';
    }
    return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#94a3b8;">🕒 PENDING</span>';
  }

  async function loadData() {
    try {
      const [stats, releasesData, ringsData, depsData] = await Promise.all([
        window.FleetAPI.getAutopatchStats().catch(() => ({})),
        window.FleetAPI.getAutopatchReleases().catch(() => ({ releases: [] })),
        window.FleetAPI.getAutopatchRings().catch(() => ({ rings: [] })),
        window.FleetAPI.getAutopatchDeployments().catch(() => ({ deployments: [] }))
      ]);

      cachedStats = stats;
      cachedReleases = releasesData.releases || [];
      cachedRings = ringsData.rings || [];
      cachedDeployments = depsData.deployments || [];
    } catch (e) {
      console.error('Failed to load Autopatch data:', e);
    }
  }

  async function render(container) {
    if (!container) {
      container = document.getElementById('view-autopatch') || document.getElementById('tab-autopatch');
    }
    if (!container) return;

    container.innerHTML = '<div style="padding:2rem;text-align:center;color:#94a3b8;"><div class="spinner"></div> Loading Windows Autopatch Release Cadence...</div>';

    await loadData();

    const stats = cachedStats || {};
    const activeRelease = stats.active_release || null;
    const fleetComp = stats.fleet_compliance_rate_percent !== undefined ? stats.fleet_compliance_rate_percent : 100;

    let html = `
      <div class="autopatch-view" style="padding: 1.5rem; max-width: 1400px; margin: 0 auto;">
        <!-- Header Banner -->
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
          <div>
            <div style="display:flex; align-items:center; gap:0.6rem;">
              <h2 style="margin: 0; font-size: 1.5rem; font-weight: 700; color: #f8fafc;">Windows Autopatch & Automated Cadence</h2>
              <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b98155; font-size: 11px; padding: 2px 8px; border-radius: 9999px;">MICROSOFT INTUNE PARITY</span>
            </div>
            <p style="margin: 0.25rem 0 0 0; color: #94a3b8; font-size: 0.9rem;">
              Staged Progressive Deployment Rings (Test ➔ First ➔ Fast ➔ Broad), Patch Tuesday Automation, Quality Gates & Rollback Safeguards
            </p>
          </div>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <button class="btn btn-secondary btn-sm" onclick="window.AutopatchTable.refresh()">
              🔄 Refresh
            </button>
            <button class="btn btn-secondary btn-sm" onclick="window.AutopatchTable.openRingsModal()">
              ⚙️ Configure Rings
            </button>
            <button class="btn btn-primary btn-sm" onclick="window.AutopatchTable.openCreateReleaseModal()" style="background:#2563eb; color:white; border:none;">
              + New Patch Cadence
            </button>
          </div>
        </div>

        <!-- KPI Metrics Grid -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Active Release Cadence</div>
            <div style="font-size: 1.15rem; font-weight: 700; color: #f8fafc; margin: 0.3rem 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
              ${activeRelease ? esc(activeRelease.name) : 'No Active Release'}
            </div>
            <div style="font-size: 0.85rem; color: #38bdf8;">
              ${activeRelease ? getPhaseBadge(activeRelease.active_phase) : '<span style="color:#64748b;">All updates broad/completed</span>'}
            </div>
          </div>

          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Fleet Compliance Rate</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: ${fleetComp >= 95 ? '#10b981' : (fleetComp >= 80 ? '#f59e0b' : '#ef4444')}; margin: 0.2rem 0;">
              ${fleetComp}%
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8;">
              ${stats.installed_deployments || 0} / ${stats.total_deployments || 0} Workstations Patched
            </div>
          </div>

          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Patch Rollout Rings</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #38bdf8; margin: 0.2rem 0;">
              4 Staged Rings
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8;">
              Test (0d) ➔ First (2d) ➔ Fast (4d) ➔ Broad (7d)
            </div>
          </div>

          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Rollout Safeguards</div>
            <div style="font-size: 1.2rem; font-weight: 700; color: ${(stats.failed_deployments || 0) > 0 ? '#ef4444' : '#10b981'}; margin: 0.35rem 0;">
              ${(stats.failed_deployments || 0) > 0 ? '⚠️ ' + stats.failed_deployments + ' Failures Detected' : '🛡️ Quality Gates Healthy'}
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8;">
              BSOD / Crash Monitoring Active
            </div>
          </div>
        </div>

        <!-- Staged Rollout Pipeline Visualizer -->
        ${renderPipelineVisualizer(activeRelease)}

        <!-- Tab Navigation Bar -->
        <div style="display: flex; gap: 0.5rem; border-bottom: 1px solid #334155; margin-bottom: 1.25rem;">
          <button class="tab-btn ${currentSubTab === 'releases' ? 'active' : ''}" onclick="window.AutopatchTable.switchSubTab('releases')"
            style="background: transparent; border: none; padding: 0.6rem 1.2rem; color: ${currentSubTab === 'releases' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${currentSubTab === 'releases' ? '#38bdf8' : 'transparent'}; font-weight: 600; cursor: pointer;">
            📅 Patch Releases Cadence (${cachedReleases.length})
          </button>
          <button class="tab-btn ${currentSubTab === 'deployments' ? 'active' : ''}" onclick="window.AutopatchTable.switchSubTab('deployments')"
            style="background: transparent; border: none; padding: 0.6rem 1.2rem; color: ${currentSubTab === 'deployments' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${currentSubTab === 'deployments' ? '#38bdf8' : 'transparent'}; font-weight: 600; cursor: pointer;">
            💻 Workstation Deployments (${cachedDeployments.length})
          </button>
          <button class="tab-btn ${currentSubTab === 'rings' ? 'active' : ''}" onclick="window.AutopatchTable.switchSubTab('rings')"
            style="background: transparent; border: none; padding: 0.6rem 1.2rem; color: ${currentSubTab === 'rings' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${currentSubTab === 'rings' ? '#38bdf8' : 'transparent'}; font-weight: 600; cursor: pointer;">
            🎯 Progressive Ring Policies (${cachedRings.length})
          </button>
        </div>

        <!-- Subtab Content View -->
        <div id="autopatch-subtab-container">
          ${currentSubTab === 'releases' ? renderReleasesTable() : (currentSubTab === 'deployments' ? renderDeploymentsTable() : renderRingsTable())}
        </div>
      </div>
    `;

    container.innerHTML = html;
  }

  function renderPipelineVisualizer(activeRelease) {
    if (!activeRelease) {
      return `
        <div class="card" style="padding: 1.2rem; background: #0f172a; border: 1px dashed #334155; border-radius: 8px; margin-bottom: 1.5rem; text-align: center; color: #94a3b8;">
          No active patch cadence in flight. Click <strong>+ New Patch Cadence</strong> to initiate a staged Windows Quality or Out-of-Band update.
        </div>
      `;
    }

    const phases = ['TEST', 'FIRST', 'FAST', 'BROAD', 'COMPLETED'];
    const currentIdx = phases.indexOf(activeRelease.active_phase);
    const isRolledBack = activeRelease.active_phase === 'ROLLED_BACK';

    const ringLabels = [
      { id: 'TEST', name: 'Test (Canary)', icon: '🧪', desc: 'IT Admin Dogsfooding (0d)' },
      { id: 'FIRST', name: 'First (1%)', icon: '🚀', desc: 'Early Adopters (2d deferral)' },
      { id: 'FAST', name: 'Fast (9%)', icon: '⚡', desc: 'Rapid Fleet (4d deferral)' },
      { id: 'BROAD', name: 'Broad (90%)', icon: '🌐', desc: 'General Availability (7d)' },
      { id: 'COMPLETED', name: 'Finalized', icon: '✅', desc: '100% Fleet Baseline' }
    ];

    return `
      <div class="card" style="padding: 1.25rem; background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; margin-bottom: 1.5rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem;">
          <div>
            <span style="font-size: 0.8rem; color: #38bdf8; font-weight: 700; text-transform: uppercase;">Current Live Pipeline</span>
            <h3 style="margin: 0.2rem 0; font-size: 1.15rem; color: #f8fafc;">${esc(activeRelease.name)} <span style="font-size:0.85rem; color:#94a3b8; font-weight:normal;">(${esc(activeRelease.target_kb_numbers)})</span></h3>
          </div>
          <div style="display: flex; gap: 0.5rem;">
            ${!isRolledBack && activeRelease.active_phase !== 'COMPLETED' ? `
              <button class="btn btn-sm btn-primary" onclick="window.AutopatchTable.progressRelease('${esc(activeRelease.id)}')" style="background: #2563eb; color:white; border:none;">
                Advance Phase ➡️
              </button>
            ` : ''}
            ${!isRolledBack ? `
              <button class="btn btn-sm btn-danger" onclick="window.AutopatchTable.openRollbackModal('${esc(activeRelease.id)}')" style="background: rgba(239,68,68,0.2); color:#ef4444; border:1px solid #ef444455;">
                🛑 Emergency Rollback
              </button>
            ` : `
              <span class="badge" style="background: rgba(239,68,68,0.2); color:#ef4444; padding: 4px 10px; font-weight:700;">ROLLED BACK: ${esc(activeRelease.rollback_reason || 'Manual Halt')}</span>
            `}
          </div>
        </div>

        <!-- Step Stages Progress Flow -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem;">
          ${ringLabels.map((step, idx) => {
            const isCurrent = step.id === activeRelease.active_phase;
            const isDone = currentIdx > idx;
            const borderCol = isRolledBack ? '#ef4444' : (isCurrent ? '#38bdf8' : (isDone ? '#10b981' : '#334155'));
            const bgCol = isCurrent ? 'rgba(56,189,248,0.08)' : (isDone ? 'rgba(16,185,129,0.05)' : '#1e293b');

            return `
              <div style="border: 1px solid ${borderCol}; background: ${bgCol}; border-radius: 6px; padding: 0.75rem; position: relative;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
                  <span style="font-size: 1.1rem;">${step.icon}</span>
                  ${isDone ? '<span style="color:#10b981; font-size:0.8rem; font-weight:700;">DONE ✓</span>' : (isCurrent ? '<span style="color:#38bdf8; font-size:0.8rem; font-weight:700; animation:pulse 2s infinite;">CURRENT</span>' : '<span style="color:#64748b; font-size:0.75rem;">QUEUED</span>')}
                </div>
                <div style="font-weight: 700; font-size: 0.9rem; color: #f8fafc;">${step.name}</div>
                <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 0.2rem;">${step.desc}</div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }

  function renderReleasesTable() {
    let releases = cachedReleases;
    if (filterReleaseType) {
      releases = releases.filter(r => r.release_type === filterReleaseType);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      releases = releases.filter(r => (r.name || '').toLowerCase().includes(q) || (r.target_kb_numbers || '').toLowerCase().includes(q));
    }

    return `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <input type="text" class="input" placeholder="Search release or KB (e.g. KB5044284)..."
            value="${esc(searchQuery)}" oninput="window.AutopatchTable.setSearch(this.value)"
            style="padding: 0.4rem 0.8rem; background: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; min-width: 280px;" />
          <select class="select" onchange="window.AutopatchTable.setFilterType(this.value)"
            style="padding: 0.4rem 0.8rem; background: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #f8fafc;">
            <option value="">All Release Types</option>
            <option value="SECURITY_QUALITY" ${filterReleaseType === 'SECURITY_QUALITY' ? 'selected' : ''}>Security Quality (B-Release)</option>
            <option value="OUT_OF_BAND_EXPEDITED" ${filterReleaseType === 'OUT_OF_BAND_EXPEDITED' ? 'selected' : ''}>Out-of-Band Expedited</option>
            <option value="OPTIONAL_PREVIEW" ${filterReleaseType === 'OPTIONAL_PREVIEW' ? 'selected' : ''}>Optional Preview (C-Release)</option>
          </select>
        </div>
      </div>

      <div class="table-container card" style="overflow-x: auto; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
        <table class="data-table" style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem;">
              <th style="padding: 0.75rem 1rem;">Release Name</th>
              <th style="padding: 0.75rem 1rem;">Month</th>
              <th style="padding: 0.75rem 1rem;">Target KBs</th>
              <th style="padding: 0.75rem 1rem;">Type</th>
              <th style="padding: 0.75rem 1rem;">Active Phase</th>
              <th style="padding: 0.75rem 1rem;">Status</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${releases.length === 0 ? `
              <tr>
                <td colspan="7" style="padding: 2rem; text-align: center; color: #94a3b8;">
                  No patch releases match current criteria.
                </td>
              </tr>
            ` : releases.map(r => `
              <tr style="border-bottom: 1px solid #334155; color: #f8fafc;">
                <td style="padding: 0.75rem 1rem; font-weight: 600;">
                  ${esc(r.name)}
                </td>
                <td style="padding: 0.75rem 1rem; color: #94a3b8;">
                  ${esc(r.release_month)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span style="font-family: monospace; background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; border: 1px solid #38bdf833;">
                    ${esc(r.target_kb_numbers)}
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span class="badge" style="background: rgba(107,114,128,0.15); color: #cbd5e1; font-size: 11px;">
                    ${esc(r.release_type)}
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem;">
                  ${getPhaseBadge(r.active_phase)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span class="badge" style="background: rgba(59,130,246,0.15); color: #60a5fa; font-size: 11px;">
                    ${esc(r.approval_status)}
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem; text-align: right; white-space: nowrap;">
                  ${r.active_phase !== 'COMPLETED' && r.active_phase !== 'ROLLED_BACK' ? `
                    <button class="btn btn-sm" onclick="window.AutopatchTable.progressRelease('${esc(r.id)}')"
                      style="background: rgba(37,99,235,0.2); color:#60a5fa; border:1px solid #2563eb55; margin-right: 4px;" title="Advance to Next Ring">
                      Advance ➔
                    </button>
                    <button class="btn btn-sm" onclick="window.AutopatchTable.openRollbackModal('${esc(r.id)}')"
                      style="background: rgba(239,68,68,0.15); color:#ef4444; border:1px solid #ef444444; margin-right: 4px;" title="Emergency Rollback">
                      🛑 Rollback
                    </button>
                  ` : ''}
                  <button class="btn btn-sm" onclick="window.AutopatchTable.deleteRelease('${esc(r.id)}')"
                    style="background: transparent; color:#94a3b8; border:none;" title="Delete Cadence">
                    🗑️
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderDeploymentsTable() {
    const deps = cachedDeployments;

    return `
      <div class="table-container card" style="overflow-x: auto; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
        <table class="data-table" style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem;">
              <th style="padding: 0.75rem 1rem;">Workstation / Device</th>
              <th style="padding: 0.75rem 1rem;">Release ID</th>
              <th style="padding: 0.75rem 1rem;">Assigned Ring</th>
              <th style="padding: 0.75rem 1rem;">Installation Status</th>
              <th style="padding: 0.75rem 1rem;">Applied KB</th>
              <th style="padding: 0.75rem 1rem;">Post-Patch Crashes</th>
              <th style="padding: 0.75rem 1rem;">Last Updated</th>
            </tr>
          </thead>
          <tbody>
            ${deps.length === 0 ? `
              <tr>
                <td colspan="7" style="padding: 2rem; text-align: center; color: #94a3b8;">
                  No device patch records recorded yet. Enrolled agents report hotfix telemetry automatically.
                </td>
              </tr>
            ` : deps.map(d => `
              <tr style="border-bottom: 1px solid #334155; color: #f8fafc;">
                <td style="padding: 0.75rem 1rem; font-weight: 600;">
                  ${esc(d.hostname || d.device_id)}
                </td>
                <td style="padding: 0.75rem 1rem; color: #94a3b8;">
                  ${esc(d.release_id)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span class="badge" style="background: rgba(139,92,246,0.15); color: #a78bfa; font-size: 11px;">
                    ${esc(d.ring_name || d.ring_id)}
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem;">
                  ${getStatusBadge(d.install_status)}
                </td>
                <td style="padding: 0.75rem 1rem; font-family: monospace; color: #38bdf8;">
                  ${esc(d.applied_kb || '—')}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span style="font-weight: 700; color: ${(d.post_patch_crashes || 0) > 0 ? '#ef4444' : '#10b981'};">
                    ${d.post_patch_crashes || 0} BSODs
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem; color: #94a3b8;">
                  ${esc(d.updated_at || d.installed_at || '—')}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderRingsTable() {
    const rings = cachedRings;

    return `
      <div class="table-container card" style="overflow-x: auto; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
        <table class="data-table" style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem;">
              <th style="padding: 0.75rem 1rem;">Phase Order</th>
              <th style="padding: 0.75rem 1rem;">Ring Name</th>
              <th style="padding: 0.75rem 1rem;">Deferral Days</th>
              <th style="padding: 0.75rem 1rem;">Target Fleet %</th>
              <th style="padding: 0.75rem 1rem;">Max Allowable Crash %</th>
              <th style="padding: 0.75rem 1rem;">Min Success Gate %</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Action</th>
            </tr>
          </thead>
          <tbody>
            ${rings.map(r => `
              <tr style="border-bottom: 1px solid #334155; color: #f8fafc;">
                <td style="padding: 0.75rem 1rem; font-weight: 700; color: #38bdf8;">
                  Phase ${r.phase_order}
                </td>
                <td style="padding: 0.75rem 1rem; font-weight: 600;">
                  ${esc(r.name)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  ${r.deferral_days} Days
                </td>
                <td style="padding: 0.75rem 1rem;">
                  ${r.target_device_percentage}%
                </td>
                <td style="padding: 0.75rem 1rem; color: #f59e0b; font-weight: 600;">
                  ${r.max_allowable_crash_rate}%
                </td>
                <td style="padding: 0.75rem 1rem; color: #10b981; font-weight: 600;">
                  ${r.min_success_rate}%
                </td>
                <td style="padding: 0.75rem 1rem; text-align: right;">
                  <button class="btn btn-sm btn-secondary" onclick="window.AutopatchTable.openEditRingModal('${esc(r.id)}', ${r.deferral_days}, ${r.max_allowable_crash_rate}, ${r.min_success_rate})">
                    Edit Gate
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  /* ── Interaction Methods ── */
  function switchSubTab(tab) {
    currentSubTab = tab;
    const container = document.getElementById('autopatch-subtab-container');
    if (container) {
      container.innerHTML = tab === 'releases' ? renderReleasesTable() : (tab === 'deployments' ? renderDeploymentsTable() : renderRingsTable());
    }
    // update tab button styles
    document.querySelectorAll('.autopatch-view .tab-btn').forEach((btn, idx) => {
      const tabs = ['releases', 'deployments', 'rings'];
      if (tabs[idx] === tab) {
        btn.style.color = '#38bdf8';
        btn.style.borderBottom = '2px solid #38bdf8';
      } else {
        btn.style.color = '#94a3b8';
        btn.style.borderBottom = '2px solid transparent';
      }
    });
  }

  function setSearch(val) {
    searchQuery = val;
    const container = document.getElementById('autopatch-subtab-container');
    if (container && currentSubTab === 'releases') {
      container.innerHTML = renderReleasesTable();
    }
  }

  function setFilterType(val) {
    filterReleaseType = val;
    const container = document.getElementById('autopatch-subtab-container');
    if (container && currentSubTab === 'releases') {
      container.innerHTML = renderReleasesTable();
    }
  }

  async function progressRelease(id) {
    if (!confirm('Are you sure you want to advance this release to the next staged deployment ring? Quality gates will be evaluated.')) return;
    try {
      await window.FleetAPI.progressAutopatchRelease(id);
      window.AutopatchTable.render();
    } catch (e) {
      alert('Failed to advance release phase: ' + e.message);
    }
  }

  async function deleteRelease(id) {
    if (!confirm('Are you sure you want to delete this Autopatch release cadence?')) return;
    try {
      await window.FleetAPI.deleteAutopatchRelease(id);
      window.AutopatchTable.render();
    } catch (e) {
      alert('Failed to delete release: ' + e.message);
    }
  }

  function openCreateReleaseModal() {
    const modalHtml = `
      <div id="autopatch-modal-backdrop" style="position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);">
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; width: 500px; max-width: 90vw; padding: 1.5rem; color: #f8fafc;">
          <h3 style="margin-top: 0; color: #f8fafc;">+ New Autopatch Release Cadence</h3>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Release Name</label>
            <input type="text" id="ap-new-name" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" placeholder="e.g. Windows 11 October 2026 Quality Update (B-Release)" />
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1rem;">
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Release Month</label>
              <input type="text" id="ap-new-month" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" value="2026-10" />
            </div>
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Release Type</label>
              <select id="ap-new-type" class="select" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;">
                <option value="SECURITY_QUALITY">Security Quality (B-Release)</option>
                <option value="OUT_OF_BAND_EXPEDITED">Out-of-Band Expedited</option>
                <option value="OPTIONAL_PREVIEW">Optional Preview (C-Release)</option>
              </select>
            </div>
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Target KB Numbers (comma separated)</label>
            <input type="text" id="ap-new-kbs" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" placeholder="e.g. KB5045000, KB5045001" />
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem;">
            <button class="btn btn-secondary" onclick="document.getElementById('autopatch-modal-backdrop').remove()">Cancel</button>
            <button class="btn btn-primary" onclick="window.AutopatchTable.submitCreateRelease()" style="background: #2563eb; color:white; border:none;">Create Cadence</button>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  async function submitCreateRelease() {
    const name = document.getElementById('ap-new-name').value.trim();
    const release_month = document.getElementById('ap-new-month').value.trim();
    const release_type = document.getElementById('ap-new-type').value;
    const target_kb_numbers = document.getElementById('ap-new-kbs').value.trim();

    if (!name || !target_kb_numbers) {
      alert('Please provide a release name and target KB numbers.');
      return;
    }

    try {
      await window.FleetAPI.createAutopatchRelease({
        name,
        release_month,
        release_type,
        target_kb_numbers,
        active_phase: 'TEST'
      });
      document.getElementById('autopatch-modal-backdrop').remove();
      window.AutopatchTable.render();
    } catch (e) {
      alert('Failed to create release: ' + e.message);
    }
  }

  function openRollbackModal(releaseId) {
    const modalHtml = `
      <div id="autopatch-modal-backdrop" style="position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);">
        <div style="background: #1e293b; border: 1px solid #ef444455; border-radius: 8px; width: 550px; max-width: 90vw; padding: 1.5rem; color: #f8fafc;">
          <h3 style="margin-top: 0; color: #ef4444; display: flex; align-items: center; gap: 0.5rem;">
            🛑 Emergency Patch Rollback & Safeguard
          </h3>
          <p style="color: #94a3b8; font-size: 0.85rem; line-height: 1.4;">
            Triggering a rollback immediately halts all further staged ring deployments, notifies workstations to cancel pending installations, and generates silent <code>wusa.exe /uninstall</code> remediation commands.
          </p>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Rollback Reason / Quality Gate Justification</label>
            <input type="text" id="ap-rollback-reason" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" placeholder="e.g. BSOD spike detected on Ring 3 endpoints" value="BSOD / crash rate threshold exceeded on endpoints" />
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem;">
            <button class="btn btn-secondary" onclick="document.getElementById('autopatch-modal-backdrop').remove()">Cancel</button>
            <button class="btn btn-danger" onclick="window.AutopatchTable.submitRollback('${esc(releaseId)}')" style="background: #ef4444; color:white; border:none;">Execute Rollback</button>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  async function submitRollback(releaseId) {
    const reason = document.getElementById('ap-rollback-reason').value.trim();
    try {
      const res = await window.FleetAPI.rollbackAutopatchRelease(releaseId, reason);
      document.getElementById('autopatch-modal-backdrop').remove();
      alert('Rollback successfully triggered! Silent removal script synthesized:\n\n' + res.rollback_script);
      window.AutopatchTable.render();
    } catch (e) {
      alert('Failed to execute rollback: ' + e.message);
    }
  }

  function openEditRingModal(ringId, deferral, crashRate, successRate) {
    const modalHtml = `
      <div id="autopatch-modal-backdrop" style="position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);">
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; width: 450px; max-width: 90vw; padding: 1.5rem; color: #f8fafc;">
          <h3 style="margin-top: 0; color: #f8fafc;">⚙️ Configure Ring Quality Gate</h3>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Ring ID</label>
            <input type="text" class="input" value="${esc(ringId)}" disabled style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #94a3b8;" />
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Deferral Days</label>
            <input type="number" id="ap-ring-deferral" class="input" value="${deferral}" min="0" max="60" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" />
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1rem;">
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Max Crash %</label>
              <input type="number" id="ap-ring-crash" step="0.1" class="input" value="${crashRate}" min="0" max="10" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" />
            </div>
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Min Success Gate %</label>
              <input type="number" id="ap-ring-success" step="0.1" class="input" value="${successRate}" min="50" max="100" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" />
            </div>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem;">
            <button class="btn btn-secondary" onclick="document.getElementById('autopatch-modal-backdrop').remove()">Cancel</button>
            <button class="btn btn-primary" onclick="window.AutopatchTable.submitUpdateRing('${esc(ringId)}')" style="background: #2563eb; color:white; border:none;">Save Gate</button>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  async function submitUpdateRing(ringId) {
    const deferral_days = parseInt(document.getElementById('ap-ring-deferral').value, 10);
    const max_allowable_crash_rate = parseFloat(document.getElementById('ap-ring-crash').value);
    const min_success_rate = parseFloat(document.getElementById('ap-ring-success').value);

    try {
      await window.FleetAPI.updateAutopatchRing(ringId, {
        deferral_days,
        max_allowable_crash_rate,
        min_success_rate
      });
      document.getElementById('autopatch-modal-backdrop').remove();
      window.AutopatchTable.render();
    } catch (e) {
      alert('Failed to update ring policy: ' + e.message);
    }
  }

  // Public API
  window.AutopatchTable = {
    init: render,
    render: render,
    refresh: render,
    switchSubTab: switchSubTab,
    setSearch: setSearch,
    setFilterType: setFilterType,
    progressRelease: progressRelease,
    deleteRelease: deleteRelease,
    openCreateReleaseModal: openCreateReleaseModal,
    submitCreateRelease: submitCreateRelease,
    openRollbackModal: openRollbackModal,
    submitRollback: submitRollback,
    openEditRingModal: openEditRingModal,
    submitUpdateRing: submitUpdateRing,
    openRingsModal: () => switchSubTab('rings')
  };
})();
