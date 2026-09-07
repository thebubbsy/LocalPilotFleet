/**
 * LocalPilot Fleet — Configuration Profiles & Settings Catalog UI Component
 * dashboard/js/components/configurationProfilesTable.js
 */

(function () {
  let _profiles = [];
  let _stats = null;
  let _catalog = [];
  let _groups = [];
  let _searchQuery = '';
  let _typeFilter = 'ALL';

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
      const [profRes, statsRes, catRes, grpRes] = await Promise.all([
        window.FleetAPI.getProfiles(),
        window.FleetAPI.getProfileStats(),
        window.FleetAPI.getSettingsCatalog(),
        window.FleetAPI.getGroups()
      ]);
      _profiles = profRes.profiles || [];
      _stats = statsRes || null;
      _catalog = catRes.catalog || [];
      _groups = grpRes.groups || [];
      render();
    } catch (err) {
      console.error('Failed to load configuration profiles:', err);
    }
  }

  function renderKpiCards() {
    const s = _stats || {
      total_profiles: _profiles.length,
      compliance_rate_percent: 100,
      evaluated_devices: 0,
      non_compliant_devices: 0
    };

    const totalMonitoredSettings = _profiles.reduce((sum, p) => sum + (p.settings_count || 0), 0);

    return `
      <div class="kpi-grid" style="margin-bottom: 20px;">
        <div class="kpi-card">
          <div class="kpi-label">Fleet Compliance Rate</div>
          <div class="kpi-value" style="color: ${s.compliance_rate_percent >= 80 ? '#10B981' : (s.compliance_rate_percent >= 50 ? '#F59E0B' : '#EF4444')};">
            ${s.compliance_rate_percent}%
          </div>
          <div class="kpi-sub">Profile baseline adherence</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Active Profiles</div>
          <div class="kpi-value">${s.total_profiles}</div>
          <div class="kpi-sub">Targeting enrolled devices</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Monitored Settings</div>
          <div class="kpi-value" style="color: #3B82F6;">${totalMonitoredSettings}</div>
          <div class="kpi-sub">OS & policy rules enforced</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Non-Compliant Nodes</div>
          <div class="kpi-value" style="color: ${s.non_compliant_devices > 0 ? '#EF4444' : '#10B981'};">
            ${s.non_compliant_devices}
          </div>
          <div class="kpi-sub">Requires policy remediation</div>
        </div>
      </div>
    `;
  }

  function renderTable() {
    const q = _searchQuery.toLowerCase();
    const filtered = _profiles.filter(p => {
      const matchSearch = p.name.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q) ||
        (p.target_group_name || '').toLowerCase().includes(q);
      const matchType = _typeFilter === 'ALL' || p.profile_type === _typeFilter;
      return matchSearch && matchType;
    });

    if (filtered.length === 0) {
      return `
        <div class="empty-state" style="padding: 48px; text-align: center; color: var(--text-muted);">
          <div style="font-size: 36px; margin-bottom: 12px;">⚙️</div>
          <div style="font-size: 16px; font-weight: 600; margin-bottom: 6px;">No Configuration Profiles Found</div>
          <p>Create a settings profile or adjust your search filter.</p>
        </div>
      `;
    }

    return `
      <table class="data-table">
        <thead>
          <tr>
            <th>Profile Name</th>
            <th>Type</th>
            <th>Target Group</th>
            <th>Settings</th>
            <th>Device Compliance</th>
            <th>Rate</th>
            <th>Last Updated</th>
            <th style="text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(p => {
            const c = p.compliance || {};
            const total = c.total_evaluated || 0;
            const comp = c.compliant || 0;
            const nonComp = c.non_compliant || 0;
            const err = c.error || 0;
            const rate = total > 0 ? c.rate_percent : 100;

            let typeBadgeClass = 'badge-settings';
            let typeLabel = 'Settings Catalog';
            if (p.profile_type === 'SecurityBaseline') {
              typeBadgeClass = 'badge-baseline';
              typeLabel = 'Security Baseline';
            } else if (p.profile_type === 'CustomPolicy') {
              typeBadgeClass = 'badge-custom';
              typeLabel = 'Custom Policy';
            }

            const compPct = total > 0 ? Math.round((comp / total) * 100) : 0;
            const nonCompPct = total > 0 ? Math.round((nonComp / total) * 100) : 0;
            const errPct = total > 0 ? Math.round((err / total) * 100) : 0;

            const updatedStr = p.updated_at ? new Date(p.updated_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Never';

            return `
              <tr data-profile-id="${esc(p.id)}">
                <td>
                  <div style="font-weight: 600; color: var(--text-bright); display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 16px;">${p.profile_type === 'SecurityBaseline' ? '🛡️' : (p.profile_type === 'CustomPolicy' ? '⚡' : '⚙️')}</span>
                    ${esc(p.name)}
                  </div>
                  <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px; max-width: 320px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                    ${esc(p.description || 'No description')}
                  </div>
                </td>
                <td>
                  <span class="badge ${typeBadgeClass}">${typeLabel}</span>
                </td>
                <td>
                  <span class="badge" style="background: ${p.target_group_color || '#3B82F6'}22; color: ${p.target_group_color || '#3B82F6'}; border: 1px solid ${p.target_group_color || '#3B82F6'}55;">
                    🏷️ ${esc(p.target_group_name || p.target_group_id)}
                  </span>
                </td>
                <td>
                  <span style="font-weight: 600;">${p.settings_count || 0}</span>
                  <span style="font-size: 11px; color: var(--text-muted);"> rules</span>
                </td>
                <td style="min-width: 140px;">
                  <div style="display: flex; height: 8px; border-radius: 4px; overflow: hidden; background: #334155; margin-bottom: 4px;">
                    <div style="width: ${compPct}%; background: #10B981;" title="${comp} Compliant"></div>
                    <div style="width: ${nonCompPct}%; background: #EF4444;" title="${nonComp} Non-compliant"></div>
                    <div style="width: ${errPct}%; background: #F59E0B;" title="${err} Error"></div>
                  </div>
                  <div style="font-size: 11px; color: var(--text-muted); display: flex; justify-content: space-between;">
                    <span style="color: #10B981;">${comp} OK</span>
                    ${nonComp > 0 ? `<span style="color: #EF4444;">${nonComp} Fail</span>` : ''}
                    ${err > 0 ? `<span style="color: #F59E0B;">${err} Err</span>` : ''}
                    <span>${total} Nodes</span>
                  </div>
                </td>
                <td>
                  <span style="font-weight: 700; color: ${rate >= 80 ? '#10B981' : (rate >= 50 ? '#F59E0B' : '#EF4444')};">
                    ${rate}%
                  </span>
                </td>
                <td style="font-size: 12px; color: var(--text-muted);">${updatedStr}</td>
                <td style="text-align: right; white-space: nowrap;">
                  <button class="intune-btn small secondary btn-inspect-profile" data-id="${esc(p.id)}" title="Inspect device compliance">
                    🔍 Inspect
                  </button>
                  <button class="intune-btn small secondary btn-edit-profile" data-id="${esc(p.id)}" title="Edit profile settings">
                    ✏️ Edit
                  </button>
                  <button class="intune-btn small danger btn-delete-profile" data-id="${esc(p.id)}" title="Delete profile">
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
    const container = document.getElementById('view-profiles');
    if (!container) return;

    container.innerHTML = `
      <style>
        .badge-settings { background: #3b82f622; color: #60a5fa; border: 1px solid #3b82f655; }
        .badge-baseline { background: #10b98122; color: #34d399; border: 1px solid #10b98155; }
        .badge-custom { background: #8b5cf622; color: #a78bfa; border: 1px solid #8b5cf655; }
        .setting-catalog-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; max-height: 380px; overflow-y: auto; padding: 4px; }
        .catalog-card { background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 12px; cursor: pointer; transition: all 0.15s; }
        .catalog-card:hover { border-color: #60a5fa; }
        .catalog-card.selected { border-color: #3b82f6; background: #1e3a5f44; }
      </style>

      <div class="intune-blade-header">
        <div class="intune-breadcrumb">Home &gt; Devices &gt; Configuration profiles</div>
        <div class="intune-title-row">
          <div class="intune-title-icon">⚙️</div>
          <div>
            <h1 class="intune-blade-title">Devices | Configuration profiles</h1>
            <p class="intune-blade-subtitle">Microsoft Intune-grade Settings Catalog, OS security baselines, and policy compliance</p>
          </div>
        </div>
      </div>

      <!-- Action Command Bar -->
      <div class="intune-command-bar" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:16px;">
        <div style="display:flex; gap:8px; align-items:center;">
          <button class="intune-btn primary" id="btn-create-profile">
            <span style="font-weight:bold; margin-right:4px;">+</span> Create profile
          </button>
          <button class="intune-btn secondary" id="btn-refresh-profiles">
            ↻ Refresh
          </button>
        </div>

        <div style="display:flex; gap:10px; align-items:center;">
          <select class="intune-input" id="profile-type-filter" style="width:160px;">
            <option value="ALL" ${_typeFilter === 'ALL' ? 'selected' : ''}>All profiles</option>
            <option value="SecurityBaseline" ${_typeFilter === 'SecurityBaseline' ? 'selected' : ''}>Security Baselines</option>
            <option value="SettingsCatalog" ${_typeFilter === 'SettingsCatalog' ? 'selected' : ''}>Settings Catalog</option>
            <option value="CustomPolicy" ${_typeFilter === 'CustomPolicy' ? 'selected' : ''}>Custom Policies</option>
          </select>
          <input class="intune-input" id="profile-search-input" type="text" placeholder="Search profiles or groups..." value="${esc(_searchQuery)}" style="width:240px;">
        </div>
      </div>

      <!-- Executive KPI Cards -->
      ${renderKpiCards()}

      <!-- Profiles Table -->
      <div class="table-container">
        ${renderTable()}
      </div>

      <!-- Create / Edit Profile Modal Container -->
      <div id="profile-editor-modal" style="display:none;"></div>

      <!-- Profile Drilldown Modal Container -->
      <div id="profile-drilldown-modal" style="display:none;"></div>
    `;

    bindEvents();
  }

  function bindEvents() {
    const searchInput = document.getElementById('profile-search-input');
    searchInput?.addEventListener('input', (e) => {
      _searchQuery = e.target.value;
      const tableContainer = document.querySelector('.table-container');
      if (tableContainer) tableContainer.innerHTML = renderTable();
      bindTableActions();
    });

    const typeFilter = document.getElementById('profile-type-filter');
    typeFilter?.addEventListener('change', (e) => {
      _typeFilter = e.target.value;
      const tableContainer = document.querySelector('.table-container');
      if (tableContainer) tableContainer.innerHTML = renderTable();
      bindTableActions();
    });

    document.getElementById('btn-refresh-profiles')?.addEventListener('click', () => {
      loadData();
      if (typeof showToast === 'function') showToast('Configuration Profiles', 'Profiles refreshed from server.', 'info');
    });

    document.getElementById('btn-create-profile')?.addEventListener('click', () => {
      openProfileEditor();
    });

    bindTableActions();
  }

  function bindTableActions() {
    document.querySelectorAll('.btn-inspect-profile').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        openDrilldownModal(id);
      });
    });

    document.querySelectorAll('.btn-edit-profile').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const prof = _profiles.find(p => p.id === id);
        if (prof) openProfileEditor(prof);
      });
    });

    document.querySelectorAll('.btn-delete-profile').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const prof = _profiles.find(p => p.id === id);
        if (confirm(`Are you sure you want to delete profile "${prof?.name || id}"? This will remove all compliance evaluation telemetry.`)) {
          try {
            await window.FleetAPI.deleteProfile(id);
            if (typeof showToast === 'function') showToast('Profile Deleted', `Deleted "${prof?.name}"`, 'warning');
            loadData();
          } catch (err) {
            alert('Failed to delete profile: ' + err.message);
          }
        }
      });
    });
  }

  /* ── Profile Creation & Editing Wizard Modal ───────────────────────── */
  function openProfileEditor(existingProfile = null) {
    const isEdit = Boolean(existingProfile);
    const modalEl = document.getElementById('profile-editor-modal');
    if (!modalEl) return;

    let currentSettings = [];
    if (isEdit && existingProfile.settings) {
      currentSettings = JSON.parse(JSON.stringify(existingProfile.settings));
    }

    modalEl.style.display = 'flex';
    modalEl.className = 'intune-modal-backdrop';
    modalEl.innerHTML = `
      <div class="intune-modal-card" style="max-width: 780px; width: 90%;">
        <div class="intune-modal-header">
          <div style="font-size: 18px; font-weight: 600; display: flex; align-items: center; gap: 8px;">
            <span>${isEdit ? '✏️ Edit Profile' : '⚙️ Create Configuration Profile'}</span>
          </div>
          <button class="intune-modal-close" id="btn-close-prof-modal">&times;</button>
        </div>

        <div class="intune-modal-body" style="padding: 20px; max-height: 650px; overflow-y: auto;">
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
            <div class="intune-form-group">
              <label class="intune-label">Profile Name *</label>
              <input class="intune-input" id="modal-prof-name" type="text" placeholder="e.g. Windows 11 Enterprise Hardened Baseline" value="${esc(existingProfile?.name || '')}">
            </div>
            <div class="intune-form-group">
              <label class="intune-label">Profile Type</label>
              <select class="intune-input" id="modal-prof-type">
                <option value="SettingsCatalog" ${existingProfile?.profile_type === 'SettingsCatalog' ? 'selected' : ''}>Settings Catalog</option>
                <option value="SecurityBaseline" ${existingProfile?.profile_type === 'SecurityBaseline' ? 'selected' : ''}>Security Baseline</option>
                <option value="CustomPolicy" ${existingProfile?.profile_type === 'CustomPolicy' ? 'selected' : ''}>Custom Policy</option>
              </select>
            </div>
          </div>

          <div class="intune-form-group" style="margin-bottom: 16px;">
            <label class="intune-label">Target Dynamic Group</label>
            <select class="intune-input" id="modal-prof-group">
              <option value="grp-all" ${(!existingProfile || existingProfile.target_group_id === 'grp-all') ? 'selected' : ''}>grp-all (All Enrolled Fleet Devices)</option>
              ${_groups.filter(g => g.id !== 'grp-all').map(g => `
                <option value="${esc(g.id)}" ${existingProfile?.target_group_id === g.id ? 'selected' : ''}>${esc(g.name)} (${esc(g.id)})</option>
              `).join('')}
            </select>
          </div>

          <div class="intune-form-group" style="margin-bottom: 16px;">
            <label class="intune-label">Description</label>
            <input class="intune-input" id="modal-prof-desc" type="text" placeholder="Policy intent and enforcement purpose..." value="${esc(existingProfile?.description || '')}">
          </div>

          <!-- Template Preset Buttons -->
          <div style="margin-bottom: 16px; background: #0f172a; padding: 12px; border-radius: 6px; border: 1px solid #334155;">
            <div style="font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 8px;">QUICK-APPLY INTUNE PRESETS</div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
              <button type="button" class="intune-btn small secondary" id="preset-security-baseline">
                🛡️ Windows 11 Hardened Baseline
              </button>
              <button type="button" class="intune-btn small secondary" id="preset-anti-telemetry">
                🔒 Zero-Telemetry & Privacy
              </button>
              <button type="button" class="intune-btn small secondary" id="preset-gaming-rig">
                ⚡ Gaming Rig Low-Latency
              </button>
            </div>
          </div>

          <!-- Settings Catalog Selector -->
          <div style="margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
            <label class="intune-label" style="margin: 0;">Settings Catalog (${_catalog.length} Available Settings)</label>
            <span id="selected-settings-counter" style="font-size: 12px; color: #60a5fa; font-weight: 600;">
              ${currentSettings.length} selected
            </span>
          </div>

          <div class="setting-catalog-grid" id="catalog-picker">
            ${_catalog.map(cat => {
              const isSelected = currentSettings.some(s => s.id === cat.id);
              const settingMatch = currentSettings.find(s => s.id === cat.id);
              const curVal = settingMatch ? settingMatch.desired_value : cat.default_value;

              return `
                <div class="catalog-card ${isSelected ? 'selected' : ''}" data-setting-id="${esc(cat.id)}">
                  <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                    <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: #334155; color: #94a3b8;">
                      ${esc(cat.category)}
                    </span>
                    <input type="checkbox" class="setting-checkbox" data-id="${esc(cat.id)}" ${isSelected ? 'checked' : ''} style="cursor: pointer;">
                  </div>
                  <div style="font-weight: 600; font-size: 13px; color: var(--text-bright); margin-bottom: 4px;">
                    ${esc(cat.name)}
                  </div>
                  <div style="font-size: 11px; color: var(--text-muted); line-height: 1.3; margin-bottom: 8px;">
                    ${esc(cat.description)}
                  </div>
                  <div style="display: flex; align-items: center; justify-content: space-between; font-size: 12px;">
                    <span style="color: #94a3b8;">Desired State:</span>
                    ${cat.setting_type === 'boolean' ? `
                      <select class="intune-input small setting-val-input" data-id="${esc(cat.id)}" style="width: 90px; padding: 2px 6px;">
                        <option value="true" ${curVal === true || curVal === 'true' ? 'selected' : ''}>Enabled</option>
                        <option value="false" ${curVal === false || curVal === 'false' ? 'selected' : ''}>Disabled</option>
                      </select>
                    ` : `
                      <input type="number" class="intune-input small setting-val-input" data-id="${esc(cat.id)}" value="${curVal}" style="width: 70px; padding: 2px 6px;">
                    `}
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>

        <div class="intune-modal-footer" style="padding: 16px 20px; border-top: 1px solid #334155; display: flex; justify-content: flex-end; gap: 10px;">
          <button class="intune-btn secondary" id="btn-cancel-prof-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-save-prof-modal">
            ${isEdit ? 'Save Changes' : 'Create Profile'}
          </button>
        </div>
      </div>
    `;

    function updateCounter() {
      const count = modalEl.querySelectorAll('.setting-checkbox:checked').length;
      const counterEl = document.getElementById('selected-settings-counter');
      if (counterEl) counterEl.textContent = `${count} selected`;
    }

    modalEl.querySelectorAll('.catalog-card').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
        const cb = card.querySelector('.setting-checkbox');
        if (cb) {
          cb.checked = !cb.checked;
          card.classList.toggle('selected', cb.checked);
          updateCounter();
        }
      });
    });

    modalEl.querySelectorAll('.setting-checkbox').forEach(cb => {
      cb.addEventListener('change', () => {
        const card = cb.closest('.catalog-card');
        if (card) card.classList.toggle('selected', cb.checked);
        updateCounter();
      });
    });

    // Preset click handlers
    document.getElementById('preset-security-baseline')?.addEventListener('click', () => {
      ['firewall_all_profiles', 'uac_enable_lua', 'rdp_nla', 'bitlocker_os_volume'].forEach(id => {
        const cb = modalEl.querySelector(`.setting-checkbox[data-id="${id}"]`);
        if (cb) {
          cb.checked = true;
          cb.closest('.catalog-card')?.classList.add('selected');
        }
      });
      document.getElementById('modal-prof-name').value = 'Windows 11 Enterprise Hardened Baseline';
      document.getElementById('modal-prof-type').value = 'SecurityBaseline';
      updateCounter();
    });

    document.getElementById('preset-anti-telemetry')?.addEventListener('click', () => {
      ['telemetry_level', 'tailored_experiences'].forEach(id => {
        const cb = modalEl.querySelector(`.setting-checkbox[data-id="${id}"]`);
        if (cb) {
          cb.checked = true;
          cb.closest('.catalog-card')?.classList.add('selected');
        }
      });
      document.getElementById('modal-prof-name').value = 'Fleet Anti-Telemetry & Diagnostic Privacy';
      document.getElementById('modal-prof-type').value = 'SettingsCatalog';
      updateCounter();
    });

    document.getElementById('preset-gaming-rig')?.addEventListener('click', () => {
      ['fast_startup'].forEach(id => {
        const cb = modalEl.querySelector(`.setting-checkbox[data-id="${id}"]`);
        if (cb) {
          cb.checked = true;
          cb.closest('.catalog-card')?.classList.add('selected');
        }
      });
      document.getElementById('modal-prof-name').value = 'Gaming Rig Low-Latency Optimization';
      document.getElementById('modal-prof-type').value = 'CustomPolicy';
      updateCounter();
    });

    // Close buttons
    const closeModal = () => { modalEl.style.display = 'none'; };
    document.getElementById('btn-close-prof-modal')?.addEventListener('click', closeModal);
    document.getElementById('btn-cancel-prof-modal')?.addEventListener('click', closeModal);

    // Save
    document.getElementById('btn-save-prof-modal')?.addEventListener('click', async () => {
      const name = document.getElementById('modal-prof-name')?.value.trim();
      const profile_type = document.getElementById('modal-prof-type')?.value;
      const target_group_id = document.getElementById('modal-prof-group')?.value;
      const description = document.getElementById('modal-prof-desc')?.value.trim();

      if (!name) {
        alert('Profile Name is required.');
        return;
      }

      // Collect selected settings
      const settings = [];
      modalEl.querySelectorAll('.setting-checkbox:checked').forEach(cb => {
        const sid = cb.getAttribute('data-id');
        const catDef = _catalog.find(c => c.id === sid);
        const valInput = modalEl.querySelector(`.setting-val-input[data-id="${sid}"]`);
        let val = catDef ? catDef.default_value : true;

        if (valInput) {
          if (catDef && catDef.setting_type === 'boolean') {
            val = valInput.value === 'true';
          } else if (catDef && catDef.setting_type === 'integer') {
            val = parseInt(valInput.value, 10) || 0;
          } else {
            val = valInput.value;
          }
        }

        settings.push({
          id: sid,
          category: catDef?.category || 'General',
          name: catDef?.name || sid,
          description: catDef?.description || '',
          setting_type: catDef?.setting_type || 'string',
          desired_value: val,
          enforce: true
        });
      });

      try {
        if (isEdit) {
          await window.FleetAPI.updateProfile(existingProfile.id, {
            name,
            description,
            profile_type,
            target_group_id,
            settings
          });
          if (typeof showToast === 'function') showToast('Profile Updated', `Saved changes to "${name}"`, 'success');
        } else {
          await window.FleetAPI.createProfile({
            name,
            description,
            profile_type,
            target_group_id,
            settings
          });
          if (typeof showToast === 'function') showToast('Profile Created', `Configured "${name}"`, 'success');
        }
        closeModal();
        loadData();
      } catch (err) {
        alert('Failed to save profile: ' + err.message);
      }
    });
  }

  /* ── Profile Compliance Drilldown Modal ────────────────────────────── */
  async function openDrilldownModal(profileId) {
    const modalEl = document.getElementById('profile-drilldown-modal');
    if (!modalEl) return;

    modalEl.style.display = 'flex';
    modalEl.className = 'intune-modal-backdrop';
    modalEl.innerHTML = `
      <div class="intune-modal-card" style="max-width: 860px; width: 95%;">
        <div class="intune-modal-header">
          <div style="font-size: 18px; font-weight: 600;">🔍 Loading Profile Compliance...</div>
          <button class="intune-modal-close" id="btn-close-drilldown-modal">&times;</button>
        </div>
        <div style="padding: 40px; text-align: center; color: var(--text-muted);">
          Fetching setting-by-setting compliance matrix from Fleet Authority...
        </div>
      </div>
    `;

    document.getElementById('btn-close-drilldown-modal')?.addEventListener('click', () => {
      modalEl.style.display = 'none';
    });

    try {
      const profile = await window.FleetAPI.getProfile(profileId);
      if (!profile) return;

      const evals = profile.evaluations || [];

      modalEl.innerHTML = `
        <div class="intune-modal-card" style="max-width: 860px; width: 95%;">
          <div class="intune-modal-header" style="border-bottom: 1px solid #334155; padding: 16px 20px;">
            <div>
              <div style="font-size: 18px; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                <span>⚙️ ${esc(profile.name)}</span>
                <span class="badge ${profile.profile_type === 'SecurityBaseline' ? 'badge-baseline' : 'badge-settings'}">
                  ${esc(profile.profile_type)}
                </span>
              </div>
              <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
                Target: 🏷️ ${esc(profile.target_group_name || profile.target_group_id)} | ${profile.settings_count} Settings Governed | ${profile.compliance?.rate_percent || 100}% Fleet Compliance
              </div>
            </div>
            <button class="intune-modal-close" id="btn-close-drilldown-modal">&times;</button>
          </div>

          <div class="intune-modal-body" style="padding: 20px; max-height: 650px; overflow-y: auto;">
            <!-- Profile Settings List -->
            <div style="margin-bottom: 20px; background: #0f172a; padding: 12px; border-radius: 6px; border: 1px solid #334155;">
              <div style="font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 8px;">PROFILE SETTINGS ENFORCED</div>
              <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                ${(profile.settings || []).map(s => `
                  <span class="badge" style="background: #1e293b; border: 1px solid #475569; color: #cbd5e1; font-size: 11px;">
                    ✓ ${esc(s.name)}: <strong>${esc(String(s.desired_value))}</strong>
                  </span>
                `).join('')}
              </div>
            </div>

            <div style="font-size: 14px; font-weight: 600; margin-bottom: 10px;">
              Device Evaluation Matrix (${evals.length} Nodes)
            </div>

            ${evals.length === 0 ? `
              <div style="padding: 32px; text-align: center; color: var(--text-muted); background: #1e293b; border-radius: 6px;">
                No devices in group "${esc(profile.target_group_name || profile.target_group_id)}" have evaluated this profile yet.
              </div>
            ` : `
              <div style="display: flex; flex-direction: column; gap: 12px;">
                ${evals.map((ev, idx) => {
                  const isCompliant = ev.compliance_status === 'COMPLIANT';
                  const isError = ev.compliance_status === 'ERROR';
                  const statusBg = isCompliant ? '#10B981' : (isError ? '#F59E0B' : '#EF4444');
                  const results = ev.setting_results || [];

                  return `
                    <div style="background: #1e293b; border: 1px solid #334155; border-radius: 6px; overflow: hidden;">
                      <div style="padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; cursor: pointer;" onclick="document.getElementById('drill-details-${idx}').classList.toggle('hidden');">
                        <div style="display: flex; align-items: center; gap: 12px;">
                          <div style="font-size: 20px;">💻</div>
                          <div>
                            <div style="font-weight: 600; color: var(--text-bright);">
                              ${esc(ev.hostname)}
                              <span style="font-size: 12px; font-weight: normal; color: var(--text-muted); margin-left: 6px;">(${esc(ev.primary_user || 'Unknown User')})</span>
                            </div>
                            <div style="font-size: 11px; color: var(--text-muted);">
                              ${esc(ev.os_name || 'Windows')} | Evaluated: ${new Date(ev.evaluated_at).toLocaleTimeString()}
                            </div>
                          </div>
                        </div>

                        <div style="display: flex; align-items: center; gap: 12px;">
                          <span class="badge" style="background: ${statusBg}22; color: ${statusBg}; border: 1px solid ${statusBg}55; font-weight: 600;">
                            ${isCompliant ? '✓ COMPLIANT' : (isError ? '⚠ ERROR' : '✗ NON-COMPLIANT')}
                          </span>
                          <span style="font-size: 12px; color: #60a5fa;">
                            ${ev.compliant_count}/${results.length} Rules OK ▼
                          </span>
                        </div>
                      </div>

                      <!-- Expandable Setting-by-Setting Breakdown -->
                      <div id="drill-details-${idx}" class="${isCompliant ? 'hidden' : ''}" style="border-top: 1px solid #334155; background: #0f172a; padding: 12px 16px;">
                        <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                          <thead>
                            <tr style="color: #94a3b8; text-align: left; border-bottom: 1px solid #1e293b;">
                              <th style="padding: 6px 0;">Setting</th>
                              <th>Category</th>
                              <th>Desired</th>
                              <th>Current</th>
                              <th>Status</th>
                              <th>Diagnostic</th>
                            </tr>
                          </thead>
                          <tbody>
                            ${results.map(r => {
                              const rOk = r.status === 'COMPLIANT';
                              const rErr = r.status === 'ERROR';
                              const rColor = rOk ? '#10B981' : (rErr ? '#F59E0B' : '#EF4444');

                              return `
                                <tr style="border-bottom: 1px solid #1e293b77;">
                                  <td style="padding: 8px 0; font-weight: 600; color: var(--text-bright);">${esc(r.name || r.id)}</td>
                                  <td style="color: #94a3b8;">${esc(r.category || 'General')}</td>
                                  <td><code>${esc(String(r.desired_value))}</code></td>
                                  <td><code>${esc(String(r.current_value))}</code></td>
                                  <td>
                                    <span style="color: ${rColor}; font-weight: 600;">
                                      ${rOk ? '✓ Pass' : (rErr ? '⚠ Error' : '✗ Fail')}
                                    </span>
                                  </td>
                                  <td style="color: var(--text-muted); font-size: 11px;">${esc(r.message || '')}</td>
                                </tr>
                              `;
                            }).join('')}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  `;
                }).join('')}
              </div>
            `}
          </div>

          <div class="intune-modal-footer" style="padding: 12px 20px; border-top: 1px solid #334155; display: flex; justify-content: flex-end;">
            <button class="intune-btn secondary" id="btn-close-drilldown-footer">Close</button>
          </div>
        </div>
      `;

      document.getElementById('btn-close-drilldown-modal')?.addEventListener('click', () => { modalEl.style.display = 'none'; });
      document.getElementById('btn-close-drilldown-footer')?.addEventListener('click', () => { modalEl.style.display = 'none'; });
    } catch (err) {
      alert('Failed to load profile details: ' + err.message);
      modalEl.style.display = 'none';
    }
  }

  // Export to window
  window.ConfigurationProfilesTable = {
    loadData
  };
})();
