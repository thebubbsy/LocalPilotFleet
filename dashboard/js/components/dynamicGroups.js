/**
 * LocalPilot Fleet — Dynamic Groups Component (Intune Style)
 * dashboard/js/components/dynamicGroups.js
 */

async function renderDynamicGroups() {
  const container = document.getElementById('groups-container');
  if (!container) return;

  container.innerHTML = `
    <div class="intune-blade-header">
      <div class="intune-breadcrumb">Home &gt; Groups &gt; All groups</div>
      <div class="intune-title-row">
        <div class="intune-title-icon">🏷️</div>
        <div>
          <h1 class="intune-blade-title">Groups | All groups</h1>
          <p class="intune-blade-subtitle">Manage device security groups and Entra ID-style dynamic membership rules</p>
        </div>
      </div>
    </div>

    <!-- Command Bar -->
    <div class="intune-command-bar">
      <button class="intune-cmd-btn primary" id="btn-new-group">
        <span class="cmd-icon">➕</span> New group
      </button>
      <button class="intune-cmd-btn" id="btn-refresh-groups">
        <span class="cmd-icon">🔄</span> Refresh
      </button>
      <div class="intune-cmd-separator"></div>
      <div class="intune-search-box">
        <span class="search-icon">🔍</span>
        <input type="text" id="group-search-input" placeholder="Search groups..." />
      </div>
    </div>

    <!-- Groups Grid -->
    <div class="intune-grid-container">
      <table class="intune-table" id="groups-table">
        <thead>
          <tr>
            <th style="width: 40px;"><input type="checkbox" id="select-all-groups" /></th>
            <th>Group name</th>
            <th>Description</th>
            <th>Group type</th>
            <th>Membership type</th>
            <th>Dynamic rule</th>
            <th>Direct members</th>
            <th style="text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody id="groups-table-body">
          <tr><td colspan="8" class="intune-loading">Loading groups...</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Create Group Modal -->
    <div id="new-group-modal" class="intune-modal" style="display: none;">
      <div class="intune-modal-backdrop"></div>
      <div class="intune-modal-dialog">
        <div class="intune-modal-header">
          <div class="modal-title">New Group</div>
          <button class="modal-close" id="modal-close-group">&times;</button>
        </div>
        <div class="intune-modal-body">
          <div class="intune-form-group">
            <label class="intune-label">Group type</label>
            <input type="text" class="intune-input" value="Security" disabled />
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Group name *</label>
            <input type="text" id="modal-group-name" class="intune-input" placeholder="e.g., Windows-HighPerf-Gaming" required />
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Group description</label>
            <input type="text" id="modal-group-desc" class="intune-input" placeholder="Targeted policies for high-performance rigs" />
          </div>
          <div class="intune-form-group">
            <label class="intune-label">Membership type</label>
            <select id="modal-membership-type" class="intune-select">
              <option value="dynamic">Dynamic Device (Rule-based)</option>
              <option value="assigned">Assigned (Static)</option>
            </select>
          </div>
          <div class="intune-form-group" id="dynamic-rule-group">
            <div class="dynamic-rule-header">
              <label class="intune-label">Dynamic membership rule (Entra ID / Intune Syntax) *</label>
              <button type="button" class="intune-link-btn" id="btn-sample-rules">Sample rules ▾</button>
            </div>
            <textarea id="modal-group-rule" class="intune-textarea code-font" rows="3" placeholder="Device.TotalRAM_GB -ge 32 -and Device.GPU -like '*NVIDIA*'"></textarea>
            <div class="rule-helper-bar">
              <button type="button" class="intune-btn secondary" id="btn-validate-rule">🔍 Validate & Test Rule</button>
              <span id="rule-test-status" class="rule-test-status"></span>
            </div>
            <div id="rule-preview-results" class="rule-preview-box" style="display:none;"></div>
          </div>
        </div>
        <div class="intune-modal-footer">
          <button class="intune-btn primary" id="btn-save-group">Create</button>
          <button class="intune-btn secondary" id="btn-cancel-group">Cancel</button>
        </div>
      </div>
    </div>
  `;

  // Bind Events
  document.getElementById('btn-refresh-groups')?.addEventListener('click', loadGroupsData);
  document.getElementById('btn-new-group')?.addEventListener('click', () => {
    document.getElementById('new-group-modal').style.display = 'flex';
  });
  document.getElementById('modal-close-group')?.addEventListener('click', () => {
    document.getElementById('new-group-modal').style.display = 'none';
  });
  document.getElementById('btn-cancel-group')?.addEventListener('click', () => {
    document.getElementById('new-group-modal').style.display = 'none';
  });

  // Rule Test
  document.getElementById('btn-validate-rule')?.addEventListener('click', async () => {
    const rule = document.getElementById('modal-group-rule').value.trim();
    const statusEl = document.getElementById('rule-test-status');
    const previewEl = document.getElementById('rule-preview-results');

    if (!rule) {
      statusEl.innerHTML = '<span class="status-error">Enter a rule expression</span>';
      return;
    }

    statusEl.innerHTML = '<span class="status-loading">Evaluating rule against fleet...</span>';
    try {
      const res = await apiFetch('/api/v1/fleet/groups/evaluate', {
        method: 'POST',
        body: JSON.stringify({ rule_expression: rule })
      });
      if (res.valid) {
        statusEl.innerHTML = `<span class="status-success">✓ Valid syntax (${res.matched_count} matching devices)</span>`;
        if (res.matched_devices && res.matched_devices.length > 0) {
          previewEl.style.display = 'block';
          previewEl.innerHTML = `<strong>Matched Devices (${res.matched_devices.length}):</strong> ` +
            res.matched_devices.map(d => `<span class="device-pill">${d.hostname}</span>`).join(' ');
        } else {
          previewEl.style.display = 'block';
          previewEl.innerHTML = `<em>No current fleet devices match this rule</em>`;
        }
      } else {
        statusEl.innerHTML = `<span class="status-error">✕ Error: ${res.error || 'Invalid syntax'}</span>`;
        previewEl.style.display = 'none';
      }
    } catch (e) {
      statusEl.innerHTML = `<span class="status-error">✕ ${e.message}</span>`;
    }
  });

  // Save Group
  document.getElementById('btn-save-group')?.addEventListener('click', async () => {
    const name = document.getElementById('modal-group-name').value.trim();
    const desc = document.getElementById('modal-group-desc').value.trim();
    const isDynamic = document.getElementById('modal-membership-type').value === 'dynamic';
    const rule = document.getElementById('modal-group-rule').value.trim();

    if (!name) {
      alert('Group name is required');
      return;
    }
    if (isDynamic && !rule) {
      alert('Dynamic rule expression is required');
      return;
    }

    try {
      await apiFetch('/api/v1/fleet/groups', {
        method: 'POST',
        body: JSON.stringify({
          name,
          description: desc,
          is_dynamic: isDynamic,
          rule_expression: isDynamic ? rule : null
        })
      });
      document.getElementById('new-group-modal').style.display = 'none';
      loadGroupsData();
      showToast('Group Created', `Security group "${name}" created successfully.`, 'success');
    } catch (e) {
      alert('Failed to create group: ' + e.message);
    }
  });

  loadGroupsData();
}

async function loadGroupsData() {
  const tbody = document.getElementById('groups-table-body');
  if (!tbody) return;

  try {
    const groups = await apiFetch('/api/v1/fleet/groups');
    if (!groups || groups.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="intune-empty">No groups found. Click "New group" to create one.</td></tr>`;
      return;
    }

    tbody.innerHTML = groups.map(g => `
      <tr class="intune-row">
        <td><input type="checkbox" class="group-select" data-id="${g.id}" /></td>
        <td>
          <div class="group-name-cell">
            <span class="group-icon">👥</span>
            <span class="group-link">${g.name}</span>
          </div>
        </td>
        <td class="text-secondary">${g.description || '—'}</td>
        <td><span class="intune-badge neutral">Security</span></td>
        <td>
          <span class="intune-badge ${g.is_dynamic ? 'blue' : 'gray'}">
            ${g.is_dynamic ? '⚡ Dynamic Device' : 'Assigned'}
          </span>
        </td>
        <td>
          <code class="code-font rule-snippet" title="${g.rule_expression || ''}">
            ${g.rule_expression ? (g.rule_expression.length > 35 ? g.rule_expression.substring(0, 35) + '...' : g.rule_expression) : '—'}
          </code>
        </td>
        <td><strong>${g.member_count ?? 0}</strong></td>
        <td style="text-align: right;">
          <button class="intune-action-icon delete" title="Delete group" onclick="deleteGroupPrompt('${g.id}', '${g.name}')">🗑️</button>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="intune-error">Error loading groups: ${e.message}</td></tr>`;
  }
}

async function deleteGroupPrompt(id, name) {
  if (confirm(`Are you sure you want to delete group "${name}"?`)) {
    try {
      await apiFetch(`/api/v1/fleet/groups/${id}`, { method: 'DELETE' });
      loadGroupsData();
      showToast('Group Deleted', `Group "${name}" has been deleted.`, 'info');
    } catch (e) {
      alert('Delete failed: ' + e.message);
    }
  }
}
