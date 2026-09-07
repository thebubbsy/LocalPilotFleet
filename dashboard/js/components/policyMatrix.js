/**
 * LocalPilot Fleet — Software & Policy Matrix Component (Intune Style)
 * dashboard/js/components/policyMatrix.js
 */

async function renderPolicyMatrix() {
  const container = document.getElementById('software-container');
  if (!container) return;

  container.innerHTML = `
    <div class="intune-blade-header">
      <div class="intune-breadcrumb">Home &gt; Apps &gt; All apps</div>
      <div class="intune-title-row">
        <div class="intune-title-icon">📦</div>
        <div>
          <h1 class="intune-blade-title">Apps | All apps</h1>
          <p class="intune-blade-subtitle">Deploy, enforce (Required), prohibit (Uninstall/Block), or make Available software across your Windows fleet</p>
        </div>
      </div>
    </div>

    <!-- Command Bar -->
    <div class="intune-command-bar">
      <button class="intune-cmd-btn primary" id="btn-add-app">
        <span class="cmd-icon">➕</span> Add app
      </button>
      <button class="intune-cmd-btn" id="btn-assign-policy">
        <span class="cmd-icon">📋</span> Assign policy
      </button>
      <button class="intune-cmd-btn" id="btn-refresh-apps">
        <span class="cmd-icon">🔄</span> Refresh
      </button>
      <div class="intune-cmd-separator"></div>
      <div class="intune-search-box">
        <span class="search-icon">🔍</span>
        <input type="text" id="app-search-input" placeholder="Filter by name or publisher..." />
      </div>
    </div>

    <!-- Policy / App Table -->
    <div class="intune-grid-container">
      <table class="intune-table" id="apps-table">
        <thead>
          <tr>
            <th style="width: 40px;"><input type="checkbox" id="select-all-apps" /></th>
            <th>Name</th>
            <th>Package ID (Winget)</th>
            <th>App type</th>
            <th>Publisher</th>
            <th>Version</th>
            <th>Assignment Intent</th>
            <th>Target Group</th>
            <th style="text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody id="apps-table-body">
          <tr><td colspan="9" class="intune-loading">Loading application catalog...</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Add App Modal -->
    <div id="add-app-modal" class="intune-modal" style="display:none;">
      <div class="intune-modal-backdrop"></div>
      <div class="intune-modal-dialog">
        <div class="intune-modal-header">
          <div class="modal-title">Select App Type & Package</div>
          <button class="modal-close" id="modal-close-app">&times;</button>
        </div>
        <div class="intune-modal-body">
          <div class="intune-form-group">
            <label class="intune-label">App type</label>
            <select id="modal-app-type" class="intune-select">
              <option value="winget">Windows app (Winget Catalog)</option>
              <option value="store">Microsoft Store app (UWP)</option>
              <option value="msi">Enterprise MSI / Standalone Executable</option>
            </select>
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Winget Package ID *</label>
            <input type="text" id="modal-app-pkgid" class="intune-input code-font" placeholder="e.g., Git.Git, Valve.Steam, Microsoft.PowerShell" required />
            <div class="form-hint">Must match the official Winget identifier</div>
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Display Name *</label>
            <input type="text" id="modal-app-name" class="intune-input" placeholder="e.g., Git for Windows" required />
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Publisher</label>
            <input type="text" id="modal-app-publisher" class="intune-input" placeholder="e.g., The Git Project" />
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Version</label>
            <input type="text" id="modal-app-version" class="intune-input" placeholder="e.g., latest" value="latest" />
          </div>
        </div>
        <div class="intune-modal-footer">
          <button class="intune-btn primary" id="btn-save-app">Add to Catalog</button>
          <button class="intune-btn secondary" id="btn-cancel-app">Cancel</button>
        </div>
      </div>
    </div>

    <!-- Policy Assignment Modal -->
    <div id="assign-policy-modal" class="intune-modal" style="display:none;">
      <div class="intune-modal-backdrop"></div>
      <div class="intune-modal-dialog">
        <div class="intune-modal-header">
          <div class="modal-title">Edit Application Assignment</div>
          <button class="modal-close" id="modal-close-policy">&times;</button>
        </div>
        <div class="intune-modal-body">
          <div class="intune-form-group">
            <label class="intune-label">Select Application *</label>
            <select id="modal-assign-software" class="intune-select"></select>
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Target Group *</label>
            <select id="modal-assign-group" class="intune-select"></select>
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Assignment Intent *</label>
            <div class="intune-radio-card-group">
              <label class="intune-radio-card">
                <input type="radio" name="intent" value="required" checked />
                <div class="radio-card-body">
                  <span class="intent-badge required">Required</span>
                  <div class="radio-desc">Enforced: automatically installed via Winget and kept up to date</div>
                </div>
              </label>
              <label class="intune-radio-card">
                <input type="radio" name="intent" value="available" />
                <div class="radio-card-body">
                  <span class="intent-badge available">Available</span>
                  <div class="radio-desc">Optional: made available for self-service install in Company Portal</div>
                </div>
              </label>
              <label class="intune-radio-card">
                <input type="radio" name="intent" value="prohibited" />
                <div class="radio-card-body">
                  <span class="intent-badge prohibited">Prohibited (Uninstall)</span>
                  <div class="radio-desc">Blocked: uninstalled immediately if discovered, and flags security alert</div>
                </div>
              </label>
            </div>
          </div>
        </div>
        <div class="intune-modal-footer">
          <button class="intune-btn primary" id="btn-save-policy">Save Assignment</button>
          <button class="intune-btn secondary" id="btn-cancel-policy">Cancel</button>
        </div>
      </div>
    </div>
  `;

  // Bind Events
  document.getElementById('btn-refresh-apps')?.addEventListener('click', loadAppsData);
  document.getElementById('btn-add-app')?.addEventListener('click', () => {
    document.getElementById('add-app-modal').style.display = 'flex';
  });
  document.getElementById('modal-close-app')?.addEventListener('click', () => {
    document.getElementById('add-app-modal').style.display = 'none';
  });
  document.getElementById('btn-cancel-app')?.addEventListener('click', () => {
    document.getElementById('add-app-modal').style.display = 'none';
  });

  document.getElementById('btn-assign-policy')?.addEventListener('click', openPolicyModal);
  document.getElementById('modal-close-policy')?.addEventListener('click', () => {
    document.getElementById('assign-policy-modal').style.display = 'none';
  });
  document.getElementById('btn-cancel-policy')?.addEventListener('click', () => {
    document.getElementById('assign-policy-modal').style.display = 'none';
  });

  // Save new app
  document.getElementById('btn-save-app')?.addEventListener('click', async () => {
    const pkg = document.getElementById('modal-app-pkgid').value.trim();
    const name = document.getElementById('modal-app-name').value.trim();
    const pub = document.getElementById('modal-app-publisher').value.trim();
    const ver = document.getElementById('modal-app-version').value.trim();

    if (!pkg || !name) {
      alert('Package ID and Display Name are required');
      return;
    }

    try {
      await apiFetch('/api/v1/fleet/software', {
        method: 'POST',
        body: JSON.stringify({ package_id: pkg, display_name: name, publisher: pub, version: ver })
      });
      document.getElementById('add-app-modal').style.display = 'none';
      loadAppsData();
      showToast('App Added', `"${name}" added to software catalog.`, 'success');
    } catch (e) {
      alert('Failed to add app: ' + e.message);
    }
  });

  // Save policy
  document.getElementById('btn-save-policy')?.addEventListener('click', async () => {
    const swId = document.getElementById('modal-assign-software').value;
    const grpId = document.getElementById('modal-assign-group').value;
    const intent = document.querySelector('input[name="intent"]:checked')?.value || 'required';

    try {
      await apiFetch('/api/v1/fleet/policies', {
        method: 'POST',
        body: JSON.stringify({ software_id: swId, group_id: grpId, intent })
      });
      document.getElementById('assign-policy-modal').style.display = 'none';
      loadAppsData();
      showToast('Policy Assigned', `App assignment intent set to ${intent.toUpperCase()}.`, 'success');
    } catch (e) {
      alert('Failed to assign policy: ' + e.message);
    }
  });

  loadAppsData();
}

async function openPolicyModal() {
  try {
    const [software, groups] = await Promise.all([
      apiFetch('/api/v1/fleet/software'),
      apiFetch('/api/v1/fleet/groups')
    ]);

    const swSelect = document.getElementById('modal-assign-software');
    const grpSelect = document.getElementById('modal-assign-group');

    swSelect.innerHTML = (software || []).map(s => `<option value="${s.id}">${s.display_name} (${s.package_id})</option>`).join('');
    grpSelect.innerHTML = (groups || []).map(g => `<option value="${g.id}">${g.name} (${g.is_dynamic ? 'Dynamic' : 'Assigned'})</option>`).join('');

    document.getElementById('assign-policy-modal').style.display = 'flex';
  } catch (e) {
    alert('Failed to load metadata: ' + e.message);
  }
}

async function loadAppsData() {
  const tbody = document.getElementById('apps-table-body');
  if (!tbody) return;

  try {
    const [software, policies, groups] = await Promise.all([
      apiFetch('/api/v1/fleet/software'),
      apiFetch('/api/v1/fleet/policies'),
      apiFetch('/api/v1/fleet/groups')
    ]);

    if (!software || software.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="intune-empty">No applications in catalog. Click "Add app" to add packages from Winget.</td></tr>`;
      return;
    }

    const groupMap = {};
    (groups || []).forEach(g => { groupMap[g.id] = g.name; });

    const policyMap = {};
    (policies || []).forEach(p => {
      if (!policyMap[p.software_id]) policyMap[p.software_id] = [];
      policyMap[p.software_id].push({
        intent: p.intent,
        groupName: groupMap[p.group_id] || p.group_id
      });
    });

    tbody.innerHTML = software.map(s => {
      const appPolicies = policyMap[s.id] || [];
      const primaryPolicy = appPolicies[0] || null;

      let intentBadge = '<span class="intune-badge gray">Unassigned</span>';
      let groupLabel = '—';

      if (primaryPolicy) {
        if (primaryPolicy.intent === 'required') {
          intentBadge = '<span class="intune-badge blue">Required</span>';
        } else if (primaryPolicy.intent === 'prohibited') {
          intentBadge = '<span class="intune-badge red">Prohibited</span>';
        } else if (primaryPolicy.intent === 'available') {
          intentBadge = '<span class="intune-badge green">Available</span>';
        }
        groupLabel = primaryPolicy.groupName;
      }

      return `
        <tr class="intune-row">
          <td><input type="checkbox" class="app-select" data-id="${s.id}" /></td>
          <td>
            <div class="app-name-cell">
              <span class="app-icon">📦</span>
              <strong>${s.display_name}</strong>
            </div>
          </td>
          <td><code class="code-font">${s.package_id}</code></td>
          <td><span class="intune-badge neutral">Windows app (Winget)</span></td>
          <td class="text-secondary">${s.publisher || '—'}</td>
          <td>${s.version || 'latest'}</td>
          <td>${intentBadge}</td>
          <td><strong>${groupLabel}</strong></td>
          <td style="text-align: right;">
            <button class="intune-action-icon" title="Edit assignment" onclick="openPolicyModal()">⚙️</button>
            <button class="intune-action-icon delete" title="Remove from catalog" onclick="deleteAppPrompt('${s.id}', '${s.display_name}')">🗑️</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" class="intune-error">Error loading apps: ${e.message}</td></tr>`;
  }
}

async function deleteAppPrompt(id, name) {
  if (confirm(`Remove application "${name}" from catalog?`)) {
    try {
      await apiFetch(`/api/v1/fleet/software/${id}`, { method: 'DELETE' });
      loadAppsData();
      showToast('App Removed', `"${name}" removed from catalog.`, 'info');
    } catch (e) {
      alert('Delete failed: ' + e.message);
    }
  }
}
