/**
 * LocalPilot Fleet — Windows 365 Cloud PC & Virtual Workstation Fleet Blade
 * dashboard/js/components/cloudPcTable.js
 */

(function () {
  'use strict';

  let currentSubTab = 'instances'; // 'instances' | 'policies' | 'snapshots'
  let cachedStats = null;
  let cachedInstances = [];
  let cachedPolicies = [];
  let cachedRestorePoints = [];
  let searchQuery = '';
  let filterStatus = '';

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getStatusBadge(status) {
    const s = String(status || 'PROVISIONED').toUpperCase();
    if (s === 'PROVISIONED') {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;font-weight:700;border:1px solid #10b98144;">✅ PROVISIONED</span>';
    } else if (s === 'PROVISIONING') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3b82f6;font-weight:700;border:1px solid #3b82f644;animation:pulse 2s infinite;">⏳ PROVISIONING</span>';
    } else if (s === 'IN_GRACE_PERIOD') {
      return '<span class="badge" style="background:rgba(245,158,11,0.2);color:#f59e0b;font-weight:700;border:1px solid #f59e0b55;">⚠️ IN GRACE PERIOD</span>';
    } else if (s === 'REPROVISIONING') {
      return '<span class="badge" style="background:rgba(139,92,246,0.2);color:#a78bfa;font-weight:700;border:1px solid #8b5cf655;animation:pulse 2s infinite;">🔄 REPROVISIONING</span>';
    } else if (s === 'OFFLINE') {
      return '<span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-weight:700;">⭕ OFFLINE</span>';
    }
    return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#94a3b8;">' + esc(s) + '</span>';
  }

  function getJoinTypeBadge(joinType) {
    const jt = String(joinType || 'ENTRA_JOIN').toUpperCase();
    if (jt === 'ENTRA_JOIN') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#60a5fa;font-size:11px;">☁️ Microsoft Entra Joined</span>';
    } else if (jt === 'HYBRID_ENTRA') {
      return '<span class="badge" style="background:rgba(139,92,246,0.15);color:#c084fc;font-size:11px;">🏢 Hybrid Entra Domain</span>';
    }
    return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#34d399;font-size:11px;">💻 Local Hyper-V Standalone</span>';
  }

  async function loadData() {
    try {
      const [stats, instData, polData, rpData] = await Promise.all([
        window.FleetAPI.getCloudPcStats().catch(() => ({})),
        window.FleetAPI.getCloudPcInstances().catch(() => ({ instances: [] })),
        window.FleetAPI.getCloudPcPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getCloudPcRestorePoints().catch(() => ({ restore_points: [] }))
      ]);

      cachedStats = stats;
      cachedInstances = instData.instances || [];
      cachedPolicies = polData.policies || [];
      cachedRestorePoints = rpData.restore_points || [];
    } catch (e) {
      console.error('Failed to load Cloud PC data:', e);
    }
  }

  async function render(container) {
    if (!container) {
      container = document.getElementById('view-cloud-pc') || document.getElementById('tab-cloud-pc');
    }
    if (!container) return;

    container.innerHTML = '<div style="padding:2rem;text-align:center;color:#94a3b8;"><div class="spinner"></div> Loading Windows 365 Cloud PC Fleet...</div>';

    await loadData();

    const stats = cachedStats || {};

    let html = `
      <div class="cloud-pc-view" style="padding: 1.5rem; max-width: 1400px; margin: 0 auto;">
        <!-- Header Banner -->
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
          <div>
            <div style="display:flex; align-items:center; gap:0.6rem;">
              <h2 style="margin: 0; font-size: 1.5rem; font-weight: 700; color: #f8fafc;">Windows 365 Cloud PC & Virtual Fleet</h2>
              <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b98155; font-size: 11px; padding: 2px 8px; border-radius: 9999px;">MICROSOFT INTUNE PARITY</span>
            </div>
            <p style="margin: 0.25rem 0 0 0; color: #94a3b8; font-size: 0.9rem;">
              Cloud PC Provisioning Policies, Hyper-V &amp; Virtual Machine Orchestration, Disaster Recovery Snapshots &amp; Lifecycle Management
            </p>
          </div>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <button class="btn btn-secondary btn-sm" onclick="window.CloudPcTable.refresh()">
              🔄 Refresh
            </button>
            <button class="btn btn-secondary btn-sm" onclick="window.CloudPcTable.openCreatePolicyModal()">
              📋 New Policy
            </button>
            <button class="btn btn-primary btn-sm" onclick="window.CloudPcTable.openCreateInstanceModal()" style="background:#2563eb; color:white; border:none;">
              + Provision Cloud PC
            </button>
          </div>
        </div>

        <!-- KPI Metrics Grid -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Total Virtual PCs</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #f8fafc; margin: 0.2rem 0;">
              ${stats.total_cloud_pcs || 0}
            </div>
            <div style="font-size: 0.8rem; color: #10b981;">
              ${stats.provisioned_count || 0} Provisioned &amp; Online
            </div>
          </div>

          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Grace &amp; Reprovisioning</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: ${(stats.in_grace_period_count || 0) > 0 ? '#f59e0b' : '#38bdf8'}; margin: 0.2rem 0;">
              ${(stats.in_grace_period_count || 0) + (stats.reprovisioning_count || 0)}
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8;">
              ${stats.in_grace_period_count || 0} in Grace &bull; ${stats.reprovisioning_count || 0} Reprovisioning
            </div>
          </div>

          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">DR Restore Points</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #a78bfa; margin: 0.2rem 0;">
              ${stats.total_restore_points || 0} Snapshots
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8;">
              Instant Disaster Recovery Ready
            </div>
          </div>

          <div class="card" style="padding: 1.1rem; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
            <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; font-weight: 600;">Allocated Virtual Storage</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #38bdf8; margin: 0.2rem 0;">
              ${stats.total_storage_allocated_gb || 0} GB
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8;">
              Across ${stats.total_policies || 0} Provisioning Policies
            </div>
          </div>
        </div>

        <!-- Tab Navigation Bar -->
        <div style="display: flex; gap: 0.5rem; border-bottom: 1px solid #334155; margin-bottom: 1.25rem;">
          <button class="tab-btn ${currentSubTab === 'instances' ? 'active' : ''}" onclick="window.CloudPcTable.switchSubTab('instances')"
            style="background: transparent; border: none; padding: 0.6rem 1.2rem; color: ${currentSubTab === 'instances' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${currentSubTab === 'instances' ? '#38bdf8' : 'transparent'}; font-weight: 600; cursor: pointer;">
            🖥️ Virtual PC Instances (${cachedInstances.length})
          </button>
          <button class="tab-btn ${currentSubTab === 'policies' ? 'active' : ''}" onclick="window.CloudPcTable.switchSubTab('policies')"
            style="background: transparent; border: none; padding: 0.6rem 1.2rem; color: ${currentSubTab === 'policies' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${currentSubTab === 'policies' ? '#38bdf8' : 'transparent'}; font-weight: 600; cursor: pointer;">
            📋 Provisioning Policies (${cachedPolicies.length})
          </button>
          <button class="tab-btn ${currentSubTab === 'snapshots' ? 'active' : ''}" onclick="window.CloudPcTable.switchSubTab('snapshots')"
            style="background: transparent; border: none; padding: 0.6rem 1.2rem; color: ${currentSubTab === 'snapshots' ? '#38bdf8' : '#94a3b8'}; border-bottom: 2px solid ${currentSubTab === 'snapshots' ? '#38bdf8' : 'transparent'}; font-weight: 600; cursor: pointer;">
            🛡️ Disaster Recovery &amp; Snapshots (${cachedRestorePoints.length})
          </button>
        </div>

        <!-- Subtab Content View -->
        <div id="cloud-pc-subtab-container">
          ${currentSubTab === 'instances' ? renderInstancesTable() : (currentSubTab === 'policies' ? renderPoliciesTable() : renderSnapshotsTable())}
        </div>
      </div>
    `;

    container.innerHTML = html;
  }

  function renderInstancesTable() {
    let instances = cachedInstances;
    if (filterStatus) {
      instances = instances.filter(i => i.provisioning_status === filterStatus);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      instances = instances.filter(i => (i.name || '').toLowerCase().includes(q) || (i.hostname || '').toLowerCase().includes(q) || (i.primary_user || '').toLowerCase().includes(q));
    }

    return `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem;">
        <div style="display: flex; gap: 0.5rem; align-items: center;">
          <input type="text" class="input" placeholder="Search Cloud PC or user..."
            value="${esc(searchQuery)}" oninput="window.CloudPcTable.setSearch(this.value)"
            style="padding: 0.4rem 0.8rem; background: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; min-width: 280px;" />
          <select class="select" onchange="window.CloudPcTable.setFilterStatus(this.value)"
            style="padding: 0.4rem 0.8rem; background: #1e293b; border: 1px solid #334155; border-radius: 6px; color: #f8fafc;">
            <option value="">All Statuses</option>
            <option value="PROVISIONED" ${filterStatus === 'PROVISIONED' ? 'selected' : ''}>Provisioned</option>
            <option value="IN_GRACE_PERIOD" ${filterStatus === 'IN_GRACE_PERIOD' ? 'selected' : ''}>In Grace Period</option>
            <option value="REPROVISIONING" ${filterStatus === 'REPROVISIONING' ? 'selected' : ''}>Reprovisioning</option>
            <option value="OFFLINE" ${filterStatus === 'OFFLINE' ? 'selected' : ''}>Offline</option>
          </select>
        </div>
      </div>

      <div class="table-container card" style="overflow-x: auto; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
        <table class="data-table" style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem;">
              <th style="padding: 0.75rem 1rem;">Cloud PC Name</th>
              <th style="padding: 0.75rem 1rem;">Primary User</th>
              <th style="padding: 0.75rem 1rem;">Hardware SKU</th>
              <th style="padding: 0.75rem 1rem;">IP Address</th>
              <th style="padding: 0.75rem 1rem;">Status</th>
              <th style="padding: 0.75rem 1rem;">Disk Free</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${instances.length === 0 ? `
              <tr>
                <td colspan="7" style="padding: 2rem; text-align: center; color: #94a3b8;">
                  No virtual Cloud PC instances match criteria.
                </td>
              </tr>
            ` : instances.map(i => `
              <tr style="border-bottom: 1px solid #334155; color: #f8fafc;">
                <td style="padding: 0.75rem 1rem;">
                  <div style="font-weight: 600; color: #f8fafc;">${esc(i.name)}</div>
                  <div style="font-size: 0.75rem; color: #38bdf8; font-family: monospace;">${esc(i.hostname)}</div>
                </td>
                <td style="padding: 0.75rem 1rem; font-weight: 600; color: #e2e8f0;">
                  👤 ${esc(i.primary_user)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span class="badge" style="background: rgba(139,92,246,0.15); color: #c084fc; font-size: 11px;">
                    ${esc(i.sku_name || 'Standard 2vCPU / 8GB')}
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem; font-family: monospace; color: #94a3b8;">
                  ${esc(i.ip_address || '—')}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  ${getStatusBadge(i.provisioning_status)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span style="color: ${(i.disk_free_gb || 0) < 20 ? '#ef4444' : '#10b981'}; font-weight: 600;">
                    ${i.disk_free_gb || 0} GB Free
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem; text-align: right; white-space: nowrap;">
                  <button class="btn btn-sm" onclick="window.CloudPcTable.openHyperVScript('${esc(i.policy_id)}', '${esc(i.name)}')"
                    style="background: rgba(59,130,246,0.15); color:#60a5fa; border:1px solid #3b82f644; margin-right: 4px;" title="View Hyper-V Provisioning Script">
                    📜 Script
                  </button>
                  <button class="btn btn-sm" onclick="window.CloudPcTable.openCreateSnapshotModal('${esc(i.id)}')"
                    style="background: rgba(139,92,246,0.15); color:#a78bfa; border:1px solid #8b5cf644; margin-right: 4px;" title="Create DR Restore Point">
                    📸 Snapshot
                  </button>
                  <button class="btn btn-sm" onclick="window.CloudPcTable.triggerReprovision('${esc(i.id)}')"
                    style="background: rgba(245,158,11,0.15); color:#f59e0b; border:1px solid #f59e0b44; margin-right: 4px;" title="Trigger Reprovisioning">
                    🔄 Reprovision
                  </button>
                  <button class="btn btn-sm" onclick="window.CloudPcTable.deleteInstance('${esc(i.id)}')"
                    style="background: transparent; color:#94a3b8; border:none;" title="Deprovision Instance">
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

  function renderPoliciesTable() {
    const policies = cachedPolicies;

    return `
      <div class="table-container card" style="overflow-x: auto; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
        <table class="data-table" style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem;">
              <th style="padding: 0.75rem 1rem;">Policy Name</th>
              <th style="padding: 0.75rem 1rem;">Hardware SKU</th>
              <th style="padding: 0.75rem 1rem;">OS Image</th>
              <th style="padding: 0.75rem 1rem;">Join Type</th>
              <th style="padding: 0.75rem 1rem;">Assigned Cloud PCs</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${policies.map(p => `
              <tr style="border-bottom: 1px solid #334155; color: #f8fafc;">
                <td style="padding: 0.75rem 1rem;">
                  <div style="font-weight: 600; color: #f8fafc;">${esc(p.name)}</div>
                  <div style="font-size: 0.75rem; color: #94a3b8;">${esc(p.description || 'No description')}</div>
                </td>
                <td style="padding: 0.75rem 1rem;">
                  <span style="font-family: monospace; color: #38bdf8;">
                    ${p.vcpu_count} vCPU &bull; ${p.ram_gb} GB RAM &bull; ${p.storage_gb} GB
                  </span>
                </td>
                <td style="padding: 0.75rem 1rem; color: #e2e8f0;">
                  ${esc(p.os_image)}
                </td>
                <td style="padding: 0.75rem 1rem;">
                  ${getJoinTypeBadge(p.join_type)}
                </td>
                <td style="padding: 0.75rem 1rem; font-weight: 700; color: #a78bfa;">
                  ${p.assigned_instances_count || 0} Instances
                </td>
                <td style="padding: 0.75rem 1rem; text-align: right;">
                  <button class="btn btn-sm btn-secondary" onclick="window.CloudPcTable.openHyperVScript('${esc(p.id)}', 'CloudPC-Preview')">
                    View Script
                  </button>
                  <button class="btn btn-sm" onclick="window.CloudPcTable.deletePolicy('${esc(p.id)}')" style="background: transparent; color:#94a3b8; border:none;">
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

  function renderSnapshotsTable() {
    const snapshots = cachedRestorePoints;

    return `
      <div class="table-container card" style="overflow-x: auto; background: #1e293b; border: 1px solid #334155; border-radius: 8px;">
        <table class="data-table" style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem;">
          <thead>
            <tr style="border-bottom: 1px solid #334155; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem;">
              <th style="padding: 0.75rem 1rem;">Snapshot Name</th>
              <th style="padding: 0.75rem 1rem;">Target Cloud PC</th>
              <th style="padding: 0.75rem 1rem;">Type</th>
              <th style="padding: 0.75rem 1rem;">Size</th>
              <th style="padding: 0.75rem 1rem;">Captured Timestamp</th>
              <th style="padding: 0.75rem 1rem;">Status</th>
              <th style="padding: 0.75rem 1rem; text-align: right;">Restore Action</th>
            </tr>
          </thead>
          <tbody>
            ${snapshots.length === 0 ? `
              <tr>
                <td colspan="7" style="padding: 2rem; text-align: center; color: #94a3b8;">
                  No disaster recovery snapshots recorded yet.
                </td>
              </tr>
            ` : snapshots.map(s => {
              const sizeGb = ((s.size_bytes || 0) / (1024 * 1024 * 1024)).toFixed(1);
              return `
                <tr style="border-bottom: 1px solid #334155; color: #f8fafc;">
                  <td style="padding: 0.75rem 1rem; font-weight: 600;">
                    📸 ${esc(s.name)}
                  </td>
                  <td style="padding: 0.75rem 1rem; color: #38bdf8;">
                    ${esc(s.cloud_pc_name || s.cloud_pc_id)}
                  </td>
                  <td style="padding: 0.75rem 1rem;">
                    <span class="badge" style="background: rgba(107,114,128,0.15); color: #cbd5e1; font-size: 11px;">
                      ${esc(s.restore_point_type)}
                    </span>
                  </td>
                  <td style="padding: 0.75rem 1rem; font-family: monospace;">
                    ${sizeGb} GB
                  </td>
                  <td style="padding: 0.75rem 1rem; color: #94a3b8;">
                    ${esc(s.captured_at)}
                  </td>
                  <td style="padding: 0.75rem 1rem;">
                    <span class="badge" style="background: rgba(16,185,129,0.15); color: #10b981; font-size: 11px;">
                      ${esc(s.status)}
                    </span>
                  </td>
                  <td style="padding: 0.75rem 1rem; text-align: right;">
                    <button class="btn btn-sm btn-primary" onclick="window.CloudPcTable.restoreSnapshot('${esc(s.id)}')"
                      style="background: #2563eb; color:white; border:none;">
                      ↩️ Restore
                    </button>
                    <button class="btn btn-sm" onclick="window.CloudPcTable.deleteSnapshot('${esc(s.id)}')" style="background: transparent; color:#94a3b8; border:none;">
                      🗑️
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

  /* ── Interactivity Methods ── */
  function switchSubTab(tab) {
    currentSubTab = tab;
    const container = document.getElementById('cloud-pc-subtab-container');
    if (container) {
      container.innerHTML = tab === 'instances' ? renderInstancesTable() : (tab === 'policies' ? renderPoliciesTable() : renderSnapshotsTable());
    }
    document.querySelectorAll('.cloud-pc-view .tab-btn').forEach((btn, idx) => {
      const tabs = ['instances', 'policies', 'snapshots'];
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
    const container = document.getElementById('cloud-pc-subtab-container');
    if (container && currentSubTab === 'instances') {
      container.innerHTML = renderInstancesTable();
    }
  }

  function setFilterStatus(val) {
    filterStatus = val;
    const container = document.getElementById('cloud-pc-subtab-container');
    if (container && currentSubTab === 'instances') {
      container.innerHTML = renderInstancesTable();
    }
  }

  async function triggerReprovision(id) {
    if (!confirm('Reprovisioning will create an automatic disaster recovery snapshot, reset OS state to factory policy, and reboot the virtual instance. Proceed?')) return;
    try {
      await window.FleetAPI.reprovisionCloudPc(id);
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to trigger reprovisioning: ' + e.message);
    }
  }

  async function restoreSnapshot(id) {
    if (!confirm('Are you sure you want to revert this Cloud PC instance to this restore point snapshot? Any changes since the snapshot will be lost.')) return;
    try {
      await window.FleetAPI.restoreCloudPcPoint(id);
      alert('Cloud PC successfully restored to selected snapshot state!');
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to restore snapshot: ' + e.message);
    }
  }

  async function deleteInstance(id) {
    if (!confirm('Deprovisioning permanently deletes this Cloud PC instance and its snapshots. Proceed?')) return;
    try {
      await window.FleetAPI.deleteCloudPcInstance(id);
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to delete instance: ' + e.message);
    }
  }

  async function deletePolicy(id) {
    if (!confirm('Delete this provisioning policy?')) return;
    try {
      await window.FleetAPI.deleteCloudPcPolicy(id);
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to delete policy: ' + e.message);
    }
  }

  async function deleteSnapshot(id) {
    if (!confirm('Delete this restore point snapshot?')) return;
    try {
      await window.FleetAPI.deleteCloudPcRestorePoint(id);
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to delete snapshot: ' + e.message);
    }
  }

  function openCreateInstanceModal() {
    const policies = cachedPolicies;
    const modalHtml = `
      <div id="cpc-modal-backdrop" style="position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);">
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; width: 500px; max-width: 90vw; padding: 1.5rem; color: #f8fafc;">
          <h3 style="margin-top: 0; color: #f8fafc;">+ Provision New Cloud PC</h3>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Instance Display Name</label>
            <input type="text" id="cpc-new-name" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" placeholder="e.g. CloudPC-Design-01" />
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1rem;">
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Hostname</label>
              <input type="text" id="cpc-new-host" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" placeholder="CPC-DES-01" />
            </div>
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Primary User</label>
              <input type="text" id="cpc-new-user" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" placeholder="e.g. Alice" />
            </div>
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Provisioning Policy / Hardware Tier</label>
            <select id="cpc-new-policy" class="select" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;">
              ${policies.map(p => `<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.sku_name)})</option>`).join('')}
            </select>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem;">
            <button class="btn btn-secondary" onclick="document.getElementById('cpc-modal-backdrop').remove()">Cancel</button>
            <button class="btn btn-primary" onclick="window.CloudPcTable.submitCreateInstance()" style="background: #2563eb; color:white; border:none;">Provision</button>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  async function submitCreateInstance() {
    const name = document.getElementById('cpc-new-name').value.trim();
    const hostname = document.getElementById('cpc-new-host').value.trim();
    const primary_user = document.getElementById('cpc-new-user').value.trim();
    const policy_id = document.getElementById('cpc-new-policy').value;

    if (!name || !hostname || !primary_user) {
      alert('Please fill in all required fields.');
      return;
    }

    try {
      await window.FleetAPI.createCloudPcInstance({
        name,
        hostname,
        primary_user,
        policy_id,
        provisioning_status: 'PROVISIONED'
      });
      document.getElementById('cpc-modal-backdrop').remove();
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to provision Cloud PC: ' + e.message);
    }
  }

  function openCreatePolicyModal() {
    const modalHtml = `
      <div id="cpc-modal-backdrop" style="position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);">
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; width: 500px; max-width: 90vw; padding: 1.5rem; color: #f8fafc;">
          <h3 style="margin-top: 0; color: #f8fafc;">📋 Create Provisioning Policy</h3>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Policy Name</label>
            <input type="text" id="cpc-pol-name" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" placeholder="e.g. Data Science Workstation" />
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem; margin-bottom: 1rem;">
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">vCPUs</label>
              <input type="number" id="cpc-pol-vcpu" class="input" value="4" min="1" max="64" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" />
            </div>
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">RAM (GB)</label>
              <input type="number" id="cpc-pol-ram" class="input" value="16" min="2" max="512" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" />
            </div>
            <div>
              <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Disk (GB)</label>
              <input type="number" id="cpc-pol-storage" class="input" value="256" min="32" max="2048" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" />
            </div>
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Join Type</label>
            <select id="cpc-pol-join" class="select" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;">
              <option value="ENTRA_JOIN">Microsoft Entra Joined</option>
              <option value="HYBRID_ENTRA">Hybrid Entra Domain</option>
              <option value="LOCAL_HYPERV_STANDALONE">Local Hyper-V Standalone</option>
            </select>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem;">
            <button class="btn btn-secondary" onclick="document.getElementById('cpc-modal-backdrop').remove()">Cancel</button>
            <button class="btn btn-primary" onclick="window.CloudPcTable.submitCreatePolicy()" style="background: #2563eb; color:white; border:none;">Create Policy</button>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  async function submitCreatePolicy() {
    const name = document.getElementById('cpc-pol-name').value.trim();
    const vcpu_count = parseInt(document.getElementById('cpc-pol-vcpu').value, 10);
    const ram_gb = parseInt(document.getElementById('cpc-pol-ram').value, 10);
    const storage_gb = parseInt(document.getElementById('cpc-pol-storage').value, 10);
    const join_type = document.getElementById('cpc-pol-join').value;

    if (!name) {
      alert('Please provide a policy name.');
      return;
    }

    try {
      await window.FleetAPI.createCloudPcPolicy({
        name,
        sku_name: `${vcpu_count}vCPU / ${ram_gb}GB RAM / ${storage_gb}GB Storage`,
        vcpu_count,
        ram_gb,
        storage_gb,
        join_type
      });
      document.getElementById('cpc-modal-backdrop').remove();
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to create policy: ' + e.message);
    }
  }

  function openCreateSnapshotModal(cpcId) {
    const modalHtml = `
      <div id="cpc-modal-backdrop" style="position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);">
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; width: 450px; max-width: 90vw; padding: 1.5rem; color: #f8fafc;">
          <h3 style="margin-top: 0; color: #f8fafc;">📸 Create Disaster Recovery Snapshot</h3>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Snapshot Name / Label</label>
            <input type="text" id="cpc-snap-name" class="input" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;" value="Manual Checkpoint ${new Date().toISOString().slice(0, 10)}" />
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display:block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.3rem;">Snapshot Type</label>
            <select id="cpc-snap-type" class="select" style="width: 100%; box-sizing: border-box; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: white;">
              <option value="USER_SNAPSHOT">Manual User Checkpoint</option>
              <option value="PRE_PATCH_RESTORE">Pre-Patch Baseline Snapshot</option>
              <option value="AUTOMATIC_DISASTER_RECOVERY">Full Disaster Recovery Backup</option>
            </select>
          </div>
          <div style="display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem;">
            <button class="btn btn-secondary" onclick="document.getElementById('cpc-modal-backdrop').remove()">Cancel</button>
            <button class="btn btn-primary" onclick="window.CloudPcTable.submitCreateSnapshot('${esc(cpcId)}')" style="background: #2563eb; color:white; border:none;">Capture Snapshot</button>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
  }

  async function submitCreateSnapshot(cpcId) {
    const name = document.getElementById('cpc-snap-name').value.trim();
    const restore_point_type = document.getElementById('cpc-snap-type').value;

    try {
      await window.FleetAPI.createCloudPcRestorePoint({
        cloud_pc_id: cpcId,
        name,
        restore_point_type
      });
      document.getElementById('cpc-modal-backdrop').remove();
      alert('Disaster recovery restore point snapshot captured!');
      window.CloudPcTable.render();
    } catch (e) {
      alert('Failed to create snapshot: ' + e.message);
    }
  }

  async function openHyperVScript(policyId, vmName) {
    try {
      const res = await window.FleetAPI.getCloudPcProvisionScript(policyId, vmName);
      const script = res.script || '';

      const modalHtml = `
        <div id="cpc-modal-backdrop" style="position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 9999; backdrop-filter: blur(4px);">
          <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; width: 650px; max-width: 90vw; padding: 1.5rem; color: #f8fafc;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1rem;">
              <h3 style="margin: 0; color: #f8fafc;">📜 Hyper-V Provisioning Automation Script</h3>
              <button class="btn btn-sm btn-secondary" onclick="navigator.clipboard.writeText(document.getElementById('cpc-script-pre').innerText); alert('Copied to clipboard!');">📋 Copy</button>
            </div>
            <pre id="cpc-script-pre" style="background: #0f172a; padding: 1rem; border-radius: 6px; border: 1px solid #334155; max-height: 350px; overflow-y: auto; font-size: 0.8rem; color: #38bdf8; font-family: monospace;">${esc(script)}</pre>
            <div style="display: flex; justify-content: flex-end; margin-top: 1rem;">
              <button class="btn btn-secondary" onclick="document.getElementById('cpc-modal-backdrop').remove()">Close</button>
            </div>
          </div>
        </div>
      `;
      document.body.insertAdjacentHTML('beforeend', modalHtml);
    } catch (e) {
      alert('Failed to generate script: ' + e.message);
    }
  }

  // Public API
  window.CloudPcTable = {
    init: render,
    render: render,
    refresh: render,
    switchSubTab: switchSubTab,
    setSearch: setSearch,
    setFilterStatus: setFilterStatus,
    triggerReprovision: triggerReprovision,
    restoreSnapshot: restoreSnapshot,
    deleteInstance: deleteInstance,
    deletePolicy: deletePolicy,
    deleteSnapshot: deleteSnapshot,
    openCreateInstanceModal: openCreateInstanceModal,
    submitCreateInstance: submitCreateInstance,
    openCreatePolicyModal: openCreatePolicyModal,
    submitCreatePolicy: submitCreatePolicy,
    openCreateSnapshotModal: openCreateSnapshotModal,
    submitCreateSnapshot: submitCreateSnapshot,
    openHyperVScript: openHyperVScript
  };
})();
