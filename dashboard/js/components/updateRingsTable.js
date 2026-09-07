/**
 * LocalPilot Fleet — Windows Update for Business (WUfB) & Update Rings UI Component
 * dashboard/js/components/updateRingsTable.js
 */

(function () {
  let _rings = [];
  let _stats = null;
  let _groups = [];
  let _searchQuery = '';
  let _channelFilter = 'ALL';

  function esc(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  async function loadData() {
    try {
      const [ringsRes, statsRes, grpRes] = await Promise.all([
        window.FleetAPI.getUpdateRings(),
        window.FleetAPI.getUpdateStats(),
        window.FleetAPI.getGroups()
      ]);
      _rings = ringsRes.rings || [];
      _stats = statsRes || null;
      _groups = grpRes.groups || [];
      render();
    } catch (err) {
      console.error('Failed to load update rings:', err);
    }
  }

  function renderKpiCards() {
    const s = _stats || {
      compliance_rate_percent: 100,
      total_rings: _rings.length,
      monitored_devices: 0,
      reboot_pending_count: 0
    };

    return `
      <div class="kpi-grid" style="margin-bottom: 20px;">
        <div class="kpi-card">
          <div class="kpi-label">Patch Compliance Rate</div>
          <div class="kpi-value" style="color: ${s.compliance_rate_percent >= 80 ? '#10B981' : (s.compliance_rate_percent >= 50 ? '#F59E0B' : '#EF4444')};">
            ${s.compliance_rate_percent}%
          </div>
          <div class="kpi-sub">Nodes compliant & up-to-date</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Pending Reboots</div>
          <div class="kpi-value" style="color: ${s.reboot_pending_count > 0 ? '#EF4444' : '#10B981'};">
            ${s.reboot_pending_count}
          </div>
          <div class="kpi-sub">Restart required to finalize patch</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Active Update Rings</div>
          <div class="kpi-value" style="color: #3B82F6;">${s.total_rings}</div>
          <div class="kpi-sub">Patch cadence policies</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Monitored Fleet Devices</div>
          <div class="kpi-value">${s.monitored_devices || 0}</div>
          <div class="kpi-sub">Reporting Windows Update state</div>
        </div>
      </div>
    `;
  }

  function renderTable() {
    const q = _searchQuery.toLowerCase();
    const filtered = _rings.filter(r => {
      const matchSearch = r.name.toLowerCase().includes(q) ||
        (r.description || '').toLowerCase().includes(q) ||
        (r.target_group_name || '').toLowerCase().includes(q);
      const matchChannel = _channelFilter === 'ALL' || r.servicing_channel === _channelFilter;
      return matchSearch && matchChannel;
    });

    if (filtered.length === 0) {
      return `
        <div class="empty-state" style="padding: 48px; text-align: center; color: var(--text-muted);">
          <div style="font-size: 36px; margin-bottom: 12px;">🔄</div>
          <div style="font-size: 16px; font-weight: 600; margin-bottom: 6px;">No Update Rings Found</div>
          <p>Create a Windows Update ring or adjust your filters.</p>
        </div>
      `;
    }

    return `
      <table class="data-table">
        <thead>
          <tr>
            <th>Ring Name</th>
            <th>Servicing Channel</th>
            <th>Target Group</th>
            <th>Quality Deferral</th>
            <th>Feature Deferral</th>
            <th>Active Hours</th>
            <th>Reboot Pending</th>
            <th>State</th>
            <th style="text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(r => {
            const stats = r.stats || {};
            const total = stats.total_devices || 0;
            const reboots = stats.reboot_pending_count || 0;
            const isPaused = r.is_paused === 1;

            let channelBadgeClass = 'badge-channel-ga';
            let channelLabel = 'General Availability';
            if (r.servicing_channel === 'WindowsInsiderBeta') {
              channelBadgeClass = 'badge-channel-beta';
              channelLabel = 'Insider Beta';
            } else if (r.servicing_channel === 'WindowsInsiderPreRelease') {
              channelBadgeClass = 'badge-channel-canary';
              channelLabel = 'Insider Pre-release';
            } else if (r.servicing_channel === 'WindowsInsiderReleasePreview') {
              channelBadgeClass = 'badge-channel-preview';
              channelLabel = 'Release Preview';
            }

            const startHr = String(r.active_hours_start).padStart(2, '0') + ':00';
            const endHr = String(r.active_hours_end).padStart(2, '0') + ':00';

            return `
              <tr data-ring-id="${esc(r.id)}">
                <td>
                  <div style="font-weight: 600; color: var(--text-bright); display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 16px;">🔄</span>
                    ${esc(r.name)}
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px; max-width: 320px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                    ${esc(r.description || 'No description')}
                  </div>
                </td>
                <td>
                  <span class="badge ${channelBadgeClass}">${channelLabel}</span>
                </td>
                <td>
                  <span class="badge" style="background: ${r.target_group_color || '#3B82F6'}22; color: ${r.target_group_color || '#3B82F6'}; border: 1px solid ${r.target_group_color || '#3B82F6'}55;">
                    🏷️ ${esc(r.target_group_name || r.target_group_id)}
                  </span>
                </td>
                <td>
                  <span style="font-weight: 600;">${r.quality_deferral_days}</span>
                  <span style="font-size: 11px; color: var(--text-muted);"> days</span>
                </td>
                <td>
                  <span style="font-weight: 600;">${r.feature_deferral_days}</span>
                  <span style="font-size: 11px; color: var(--text-muted);"> days</span>
                </td>
                <td>
                  <span style="font-size: 12px; font-family: monospace; background: #1e293b; padding: 2px 6px; border-radius: 4px; border: 1px solid #334155;">
                    ${startHr} - ${endHr}
                  </span>
                </td>
                <td>
                  ${reboots > 0 ? `
                    <span class="badge" style="background:#EF444422; color:#EF4444; border:1px solid #EF444455; font-weight:600;">
                      ⚠️ ${reboots} Pending
                    </span>
                  ` : `
                    <span class="badge" style="background:#10B98122; color:#10B981; border:1px solid #10B98155;">
                      ✓ 0 Pending
                    </span>
                  `}
                </td>
                <td>
                  ${isPaused ? `
                    <span class="badge" style="background:#F59E0B22; color:#F59E0B; border:1px solid #F59E0B55;">
                      ⏸️ Paused
                    </span>
                  ` : `
                    <span class="badge" style="background:#10B98122; color:#10B981; border:1px solid #10B98155;">
                      ▶️ Active
                    </span>
                  `}
                </td>
                <td style="text-align: right; white-space: nowrap;">
                  <button class="intune-btn small secondary btn-inspect-ring" data-id="${esc(r.id)}" title="Inspect assigned devices & updates">
                    🔍 Inspect
                  </button>
                  <button class="intune-btn small secondary btn-toggle-pause-ring" data-id="${esc(r.id)}" data-paused="${isPaused ? '1' : '0'}" title="${isPaused ? 'Resume update ring' : 'Pause update ring'}">
                    ${isPaused ? '▶️ Resume' : '⏸️ Pause'}
                  </button>
                  <button class="intune-btn small secondary btn-edit-ring" data-id="${esc(r.id)}" title="Edit update ring parameters">
                    ✏️ Edit
                  </button>
                  <button class="intune-btn small danger btn-delete-ring" data-id="${esc(r.id)}" title="Delete update ring">
                    🗑️
                  </button>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function render() {
    const container = document.getElementById('view-updates');
    if (!container) return;

    container.innerHTML = `
      <style>
        .badge-channel-ga { background: #10b98122; color: #34d399; border: 1px solid #10b98155; }
        .badge-channel-beta { background: #3b82f622; color: #60a5fa; border: 1px solid #3b82f655; }
        .badge-channel-canary { background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b55; }
        .badge-channel-preview { background: #8b5cf622; color: #a78bfa; border: 1px solid #8b5cf655; }
        .hotfix-pill { display: inline-block; background: #1e293b; border: 1px solid #334155; border-radius: 4px; padding: 2px 6px; font-size: 11px; margin: 2px; font-family: monospace; }
      </style>

      <div class="intune-blade-header">
        <div class="intune-breadcrumb">Home &gt; Devices &gt; Windows update rings</div>
        <div class="intune-title-row">
          <div class="intune-title-icon">🔄</div>
          <div>
            <h1 class="intune-blade-title">Devices | Windows update rings</h1>
            <p class="intune-blade-subtitle">Windows Update for Business (WUfB) patch cadence, active hours, deferrals, and pending reboot tracking</p>
          </div>
        </div>
      </div>

      <!-- Action Command Bar -->
      <div class="intune-command-bar" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:16px;">
        <div style="display:flex; gap:8px; align-items:center;">
          <button class="intune-btn primary" id="btn-create-ring">
            <span style="font-weight:bold; margin-right:4px;">+</span> Create update ring
          </button>
          <button class="intune-btn secondary" id="btn-refresh-rings">
            ↻ Refresh
          </button>
        </div>

        <div style="display:flex; gap:10px; align-items:center;">
          <select class="intune-input" id="ring-channel-filter" style="width:180px;">
            <option value="ALL" ${_channelFilter === 'ALL' ? 'selected' : ''}>All channels</option>
            <option value="GeneralAvailability" ${_channelFilter === 'GeneralAvailability' ? 'selected' : ''}>General Availability</option>
            <option value="WindowsInsiderBeta" ${_channelFilter === 'WindowsInsiderBeta' ? 'selected' : ''}>Insider Beta</option>
            <option value="WindowsInsiderPreRelease" ${_channelFilter === 'WindowsInsiderPreRelease' ? 'selected' : ''}>Insider Canary</option>
            <option value="WindowsInsiderReleasePreview" ${_channelFilter === 'WindowsInsiderReleasePreview' ? 'selected' : ''}>Release Preview</option>
          </select>
          <input class="intune-input" id="ring-search-input" type="text" placeholder="Search rings or groups..." value="${esc(_searchQuery)}" style="width:240px;">
        </div>
      </div>

      <!-- Executive KPI Cards -->
      ${renderKpiCards()}

      <!-- Update Rings Data Table -->
      <div class="intune-card" style="padding: 0; overflow-x: auto;">
        ${renderTable()}
      </div>

      <!-- Container for Dynamic Modals -->
      <div id="update-ring-modal-container"></div>
    `;

    bindEvents();
  }

  function bindEvents() {
    document.getElementById('btn-create-ring')?.addEventListener('click', () => {
      openCreateRingModal();
    });

    document.getElementById('btn-refresh-rings')?.addEventListener('click', () => {
      loadData();
    });

    document.getElementById('ring-channel-filter')?.addEventListener('change', (e) => {
      _channelFilter = e.target.value;
      render();
    });

    document.getElementById('ring-search-input')?.addEventListener('input', (e) => {
      _searchQuery = e.target.value;
      render();
    });

    document.querySelectorAll('.btn-inspect-ring').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        openInspectRingModal(id);
      });
    });

    document.querySelectorAll('.btn-edit-ring').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        const ring = _rings.find(r => r.id === id);
        if (ring) openCreateRingModal(ring);
      });
    });

    document.querySelectorAll('.btn-toggle-pause-ring').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        const currentPaused = e.currentTarget.getAttribute('data-paused') === '1';
        try {
          await window.FleetAPI.updateUpdateRing(id, { is_paused: currentPaused ? 0 : 1 });
          if (window.showToast) window.showToast('Update Ring', `Ring ${currentPaused ? 'resumed' : 'paused'} successfully.`, 'success');
          loadData();
        } catch (err) {
          alert('Failed to update ring state: ' + err.message);
        }
      });
    });

    document.querySelectorAll('.btn-delete-ring').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        const ring = _rings.find(r => r.id === id);
        if (!confirm(`Are you sure you want to delete update ring "${ring?.name || id}"?`)) return;

        try {
          await window.FleetAPI.deleteUpdateRing(id);
          if (window.showToast) window.showToast('Update Ring Deleted', 'Update ring removed successfully.', 'info');
          loadData();
        } catch (err) {
          alert('Failed to delete ring: ' + err.message);
        }
      });
    });
  }

  function openCreateRingModal(editingRing = null) {
    const isEdit = !!editingRing;
    const modalContainer = document.getElementById('update-ring-modal-container');
    if (!modalContainer) return;

    modalContainer.innerHTML = `
      <div class="modal-backdrop" id="ring-modal-backdrop" style="position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:9999;">
        <div class="modal-card" style="background:#0f172a; border:1px solid #334155; border-radius:8px; width:680px; max-width:92vw; max-height:90vh; overflow-y:auto; box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
          <div style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid #334155;">
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="font-size:20px;">🔄</span>
              <h2 style="font-size:16px; font-weight:600; margin:0;">${isEdit ? 'Edit Update Ring' : 'Create Windows Update Ring'}</h2>
            </div>
            <button id="modal-ring-close" style="background:none; border:none; color:#94a3b8; font-size:20px; cursor:pointer;">&times;</button>
          </div>

          <div style="padding:20px; display:flex; flex-direction:column; gap:16px;">
            ${!isEdit ? `
              <div class="intune-form-group">
                <label class="intune-label">Configuration Preset</label>
                <select class="intune-input" id="ring-preset-select">
                  <option value="">Custom Policy (Configure manually)</option>
                  <option value="canary">Fast Ring (Canary / IT Pilot - 0 days deferral, 2-day deadline)</option>
                  <option value="production" selected>Broad Production (General Availability - 7 days quality, 30 days feature)</option>
                  <option value="gaming">Gaming Rig / High Latency VIP (14 days deferral, active hours 08:00 - 02:00, Notify only)</option>
                </select>
              </div>
            ` : ''}

            <div class="intune-form-group">
              <label class="intune-label">Ring Name *</label>
              <input class="intune-input" id="modal-ring-name" type="text" placeholder="e.g. Ring 2: Broad Production Fleet" value="${esc(editingRing?.name || '')}" required>
            </div>

            <div class="intune-form-group">
              <label class="intune-label">Description</label>
              <input class="intune-input" id="modal-ring-desc" type="text" placeholder="e.g. Standard enterprise patch cadence with 7-day validation buffer" value="${esc(editingRing?.description || '')}">
            </div>

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Target Dynamic Group</label>
                <select class="intune-input" id="modal-ring-group">
                  <option value="grp-all" ${editingRing?.target_group_id === 'grp-all' ? 'selected' : ''}>All Enrolled Devices (grp-all)</option>
                  ${_groups.map(g => `
                    <option value="${esc(g.id)}" ${editingRing?.target_group_id === g.id ? 'selected' : ''}>
                      ${esc(g.name)} (${esc(g.id)})
                    </option>
                  `).join('')}
                </select>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Servicing Channel</label>
                <select class="intune-input" id="modal-ring-channel">
                  <option value="GeneralAvailability" ${editingRing?.servicing_channel === 'GeneralAvailability' ? 'selected' : ''}>General Availability</option>
                  <option value="WindowsInsiderBeta" ${editingRing?.servicing_channel === 'WindowsInsiderBeta' ? 'selected' : ''}>Windows Insider Beta</option>
                  <option value="WindowsInsiderPreRelease" ${editingRing?.servicing_channel === 'WindowsInsiderPreRelease' ? 'selected' : ''}>Windows Insider Pre-release (Canary)</option>
                  <option value="WindowsInsiderReleasePreview" ${editingRing?.servicing_channel === 'WindowsInsiderReleasePreview' ? 'selected' : ''}>Windows Insider Release Preview</option>
                </select>
              </div>
            </div>

            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Quality Update Deferral (Days: 0-30)</label>
                <input class="intune-input" id="modal-ring-quality" type="number" min="0" max="30" value="${editingRing ? editingRing.quality_deferral_days : 7}">
                <div class="form-hint">Number of days to defer cumulative security updates</div>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Feature Update Deferral (Days: 0-365)</label>
                <input class="intune-input" id="modal-ring-feature" type="number" min="0" max="365" value="${editingRing ? editingRing.feature_deferral_days : 30}">
                <div class="form-hint">Number of days to defer annual Windows feature upgrades</div>
              </div>
            </div>

            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Active Hours Start</label>
                <input class="intune-input" id="modal-ring-ah-start" type="number" min="0" max="23" value="${editingRing ? editingRing.active_hours_start : 8}">
                <div class="form-hint">0 - 23 (24hr clock)</div>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Active Hours End</label>
                <input class="intune-input" id="modal-ring-ah-end" type="number" min="0" max="23" value="${editingRing ? editingRing.active_hours_end : 17}">
                <div class="form-hint">0 - 23 (24hr clock)</div>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Restart Deadline (Days)</label>
                <input class="intune-input" id="modal-ring-deadline" type="number" min="0" max="30" value="${editingRing ? editingRing.restart_deadline_days : 5}">
                <div class="form-hint">Grace period before reboot</div>
              </div>
            </div>

            <div class="intune-form-group">
              <label class="intune-label">Automatic Update Behavior</label>
              <select class="intune-input" id="modal-ring-mode">
                <option value="AutoInstallAndRebootAtMaintenanceTime" ${editingRing?.automatic_update_mode === 'AutoInstallAndRebootAtMaintenanceTime' ? 'selected' : ''}>Auto install and reboot at maintenance time</option>
                <option value="NotifyDownload" ${editingRing?.automatic_update_mode === 'NotifyDownload' ? 'selected' : ''}>Notify download (Recommended for gaming rigs)</option>
                <option value="AutoInstallAndRebootWithoutEndUserControl" ${editingRing?.automatic_update_mode === 'AutoInstallAndRebootWithoutEndUserControl' ? 'selected' : ''}>Auto install and reboot without end-user control (Strict)</option>
              </select>
            </div>
          </div>

          <div style="display:flex; justify-content:flex-end; gap:10px; padding:16px 20px; border-top:1px solid #334155; background:#0b1120;">
            <button class="intune-btn secondary" id="modal-ring-cancel">Cancel</button>
            <button class="intune-btn primary" id="modal-ring-save">${isEdit ? 'Save Changes' : 'Create Ring'}</button>
          </div>
        </div>
      </div>
    `;

    // Presets listener
    document.getElementById('ring-preset-select')?.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val === 'canary') {
        document.getElementById('modal-ring-name').value = 'Ring 1: Fast Canary Ring';
        document.getElementById('modal-ring-desc').value = 'Zero-day patch validation for IT pilot machines & disposable VMs';
        document.getElementById('modal-ring-channel').value = 'WindowsInsiderBeta';
        document.getElementById('modal-ring-quality').value = 0;
        document.getElementById('modal-ring-feature').value = 0;
        document.getElementById('modal-ring-ah-start').value = 9;
        document.getElementById('modal-ring-ah-end').value = 18;
        document.getElementById('modal-ring-deadline').value = 2;
        document.getElementById('modal-ring-mode').value = 'AutoInstallAndRebootAtMaintenanceTime';
      } else if (val === 'production') {
        document.getElementById('modal-ring-name').value = 'Ring 2: Broad Production Fleet';
        document.getElementById('modal-ring-desc').value = 'Standard enterprise patch cadence with 7-day validation buffer';
        document.getElementById('modal-ring-channel').value = 'GeneralAvailability';
        document.getElementById('modal-ring-quality').value = 7;
        document.getElementById('modal-ring-feature').value = 30;
        document.getElementById('modal-ring-ah-start').value = 8;
        document.getElementById('modal-ring-ah-end').value = 17;
        document.getElementById('modal-ring-deadline').value = 5;
        document.getElementById('modal-ring-mode').value = 'AutoInstallAndRebootAtMaintenanceTime';
      } else if (val === 'gaming') {
        document.getElementById('modal-ring-name').value = 'Ring 3: Gaming & Low Latency VIP';
        document.getElementById('modal-ring-desc').value = 'Extended active hours and notify-only policy to prevent game interruptions';
        document.getElementById('modal-ring-channel').value = 'GeneralAvailability';
        document.getElementById('modal-ring-quality').value = 14;
        document.getElementById('modal-ring-feature').value = 90;
        document.getElementById('modal-ring-ah-start').value = 8;
        document.getElementById('modal-ring-ah-end').value = 2;
        document.getElementById('modal-ring-deadline').value = 14;
        document.getElementById('modal-ring-mode').value = 'NotifyDownload';
      }
    });

    const closeModal = () => { modalContainer.innerHTML = ''; };
    document.getElementById('modal-ring-close')?.addEventListener('click', closeModal);
    document.getElementById('modal-ring-cancel')?.addEventListener('click', closeModal);

    document.getElementById('modal-ring-save')?.addEventListener('click', async () => {
      const name = document.getElementById('modal-ring-name')?.value?.trim();
      if (!name) {
        alert('Ring name is required');
        return;
      }

      const payload = {
        name,
        description: document.getElementById('modal-ring-desc')?.value?.trim() || '',
        target_group_id: document.getElementById('modal-ring-group')?.value || 'grp-all',
        servicing_channel: document.getElementById('modal-ring-channel')?.value || 'GeneralAvailability',
        quality_deferral_days: parseInt(document.getElementById('modal-ring-quality')?.value || '0', 10),
        feature_deferral_days: parseInt(document.getElementById('modal-ring-feature')?.value || '0', 10),
        active_hours_start: parseInt(document.getElementById('modal-ring-ah-start')?.value || '8', 10),
        active_hours_end: parseInt(document.getElementById('modal-ring-ah-end')?.value || '17', 10),
        restart_deadline_days: parseInt(document.getElementById('modal-ring-deadline')?.value || '5', 10),
        automatic_update_mode: document.getElementById('modal-ring-mode')?.value || 'AutoInstallAndRebootAtMaintenanceTime'
      };

      try {
        if (isEdit) {
          await window.FleetAPI.updateUpdateRing(editingRing.id, payload);
          if (window.showToast) window.showToast('Update Ring Updated', `Ring "${name}" modified.`, 'success');
        } else {
          await window.FleetAPI.createUpdateRing(payload);
          if (window.showToast) window.showToast('Update Ring Created', `Ring "${name}" configured.`, 'success');
        }
        closeModal();
        loadData();
      } catch (err) {
        alert('Failed to save update ring: ' + err.message);
      }
    });
  }

  async function openInspectRingModal(ringId) {
    const modalContainer = document.getElementById('update-ring-modal-container');
    if (!modalContainer) return;

    modalContainer.innerHTML = `
      <div class="modal-backdrop" id="inspect-modal-backdrop" style="position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:9999;">
        <div class="modal-card" style="background:#0f172a; border:1px solid #334155; border-radius:8px; width:760px; max-width:92vw; max-height:90vh; overflow-y:auto;">
          <div style="padding:24px; text-align:center;">
            <div style="font-size:24px; margin-bottom:8px;">⏳</div>
            <div>Loading ring patch telemetry...</div>
          </div>
        </div>
      </div>
    `;

    try {
      const ring = await window.FleetAPI.getUpdateRing(ringId);
      const devices = ring.devices || [];

      modalContainer.innerHTML = `
        <div class="modal-backdrop" id="inspect-modal-backdrop" style="position:fixed; inset:0; background:rgba(0,0,0,0.7); display:flex; align-items:center; justify-content:center; z-index:9999;">
          <div class="modal-card" style="background:#0f172a; border:1px solid #334155; border-radius:8px; width:780px; max-width:94vw; max-height:90vh; overflow-y:auto; box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
            <div style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid #334155;">
              <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-size:20px;">🔄</span>
                <div>
                  <h2 style="font-size:16px; font-weight:600; margin:0;">${esc(ring.name)}</h2>
                  <div style="font-size:12px; color:var(--text-muted);">${esc(ring.servicing_channel)} &bull; ${devices.length} Assigned Devices</div>
                </div>
              </div>
              <button id="modal-inspect-close" style="background:none; border:none; color:#94a3b8; font-size:20px; cursor:pointer;">&times;</button>
            </div>

            <div style="padding:20px;">
              <h3 style="font-size:14px; font-weight:600; margin-bottom:12px;">Assigned Fleet Nodes & Patch Status</h3>
              ${devices.length === 0 ? `
                <div style="padding:32px; text-align:center; color:var(--text-muted); background:#1e293b; border-radius:6px;">
                  No devices currently reporting telemetry under this ring. Nodes will report during their next heartbeat.
                </div>
              ` : `
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>Device</th>
                      <th>Compliance</th>
                      <th>Reboot Pending</th>
                      <th>Recent Hotfixes</th>
                      <th style="text-align:right;">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${devices.map(d => {
                      const isPending = d.reboot_pending === 1;
                      const hotfixes = d.installed_hotfixes || [];
                      const reasons = d.reboot_pending_reasons || [];

                      return `
                        <tr>
                          <td>
                            <div style="font-weight:600; color:var(--text-bright);">💻 ${esc(d.hostname)}</div>
                            <div style="font-size:11px; color:var(--text-muted);">${esc(d.primary_user || 'SYSTEM')} &bull; ${esc(d.os_version || 'Windows 11')}</div>
                          </td>
                          <td>
                            ${d.compliance_status === 'COMPLIANT' ? `
                              <span class="badge" style="background:#10b98122; color:#10b981; border:1px solid #10b98155;">✓ Compliant</span>
                            ` : `
                              <span class="badge" style="background:#ef444422; color:#ef4444; border:1px solid #ef444455;">⚠️ ${esc(d.compliance_status)}</span>
                            `}
                          </td>
                          <td>
                            ${isPending ? `
                              <div style="color:#ef4444; font-weight:600; font-size:12px;">⚠️ Reboot Required</div>
                              ${reasons.length > 0 ? `
                                <div style="font-size:10px; color:#f87171; font-family:monospace; margin-top:2px;">
                                  ${esc(reasons.join(', '))}
                                </div>
                              ` : ''}
                            ` : `
                              <span style="color:#10b981; font-size:12px;">✓ Clean</span>
                            `}
                          </td>
                          <td style="max-width:240px;">
                            ${hotfixes.length > 0 ? hotfixes.slice(0, 3).map(hf => `
                              <span class="hotfix-pill" title="${esc(hf.description || '')}">${esc(hf.hotfix_id)}</span>
                            `).join('') : '<span style="font-size:11px; color:var(--text-muted);">None reported</span>'}
                          </td>
                          <td style="text-align:right;">
                            <button class="intune-btn small primary btn-scan-now" data-device-id="${esc(d.device_id)}" title="Queue immediate Windows Update scan">
                              ⚡ Scan now
                            </button>
                          </td>
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              `}
            </div>

            <div style="display:flex; justify-content:flex-end; padding:16px 20px; border-top:1px solid #334155; background:#0b1120;">
              <button class="intune-btn secondary" id="modal-inspect-close-btn">Close</button>
            </div>
          </div>
        </div>
      `;

      const closeInspect = () => { modalContainer.innerHTML = ''; };
      document.getElementById('modal-inspect-close')?.addEventListener('click', closeInspect);
      document.getElementById('modal-inspect-close-btn')?.addEventListener('click', closeInspect);

      modalContainer.querySelectorAll('.btn-scan-now').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const devId = e.currentTarget.getAttribute('data-device-id');
          try {
            await window.FleetAPI.scanDeviceUpdates(devId);
            if (window.showToast) window.showToast('Update Scan Queued', 'Windows Update scan dispatched to node.', 'info');
          } catch (err) {
            alert('Failed to dispatch update scan: ' + err.message);
          }
        });
      });
    } catch (err) {
      alert('Failed to load ring details: ' + err.message);
      modalContainer.innerHTML = '';
    }
  }

  // Export globally
  window.UpdateRingsTable = {
    loadData
  };
})();
