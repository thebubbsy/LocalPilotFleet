/**
 * LocalPilot Fleet — Intune Endpoint Security > Attack Surface Reduction Blade
 * dashboard/js/components/asrTable.js
 *
 * Full Intune-style ASR management: policy catalog, live event feed, device posture.
 */

(function () {
  'use strict';

  const ASR_RULE_NAMES = {
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'Block executable content from email client and webmail',
    '3b576869-a4ec-4529-8536-b80a7769e899': 'Block Office apps from creating executable content',
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': 'Block Office apps from injecting code into other processes',
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a': 'Block Office apps from creating child processes',
    '26190899-1602-49e8-8b27-eb1d0a1ce869': 'Block Win32 API calls from Office macros',
    'e6db77e5-3df2-4cf1-b95a-636979351e5b': 'Block persistence through WMI event subscription',
    'd3e037e1-3eb8-44c8-a917-57927947596d': 'Block JavaScript or VBScript from launching downloaded executable content',
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc': 'Block execution of potentially obfuscated scripts',
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b': 'Block Win32 imports from Macro code in Office',
    '01443614-cd74-433a-b99e-2ecdc07bfc25': 'Block executable files from running unless they meet a prevalence criterion',
    'c1db55ab-c21a-4637-bb3f-a12568109d35': 'Use advanced protection against ransomware',
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0': 'Block credential stealing from Windows LSASS',
    'd1e49aac-8f56-4280-b9ba-993a6d77406c': 'Block process creations originating from PSExec and WMI commands',
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': 'Block untrusted and unsigned processes from USB',
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb': 'Block Adobe Reader from creating child processes',
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': 'Block Office communication apps from creating child processes'
  };

  const ASR_PRESETS = {
    audit: {
      label: '🛡️ ASR Audit Baseline',
      rules: Object.fromEntries(Object.keys(ASR_RULE_NAMES).map(k => [k, 'AUDIT'])),
      network_protection_mode: 'AUDIT',
      controlled_folder_access: 'AUDIT'
    },
    block: {
      label: '🚫 Zero-Trust Block Hardened',
      rules: Object.fromEntries(Object.keys(ASR_RULE_NAMES).map(k => [k, 'BLOCK'])),
      network_protection_mode: 'BLOCK',
      controlled_folder_access: 'BLOCK'
    },
    gaming: {
      label: '🎮 Gaming Rig Minimal ASR',
      rules: {
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'BLOCK',
        '3b576869-a4ec-4529-8536-b80a7769e899': 'AUDIT',
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': 'AUDIT',
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a': 'AUDIT',
        '26190899-1602-49e8-8b27-eb1d0a1ce869': 'AUDIT',
        'e6db77e5-3df2-4cf1-b95a-636979351e5b': 'BLOCK',
        'd3e037e1-3eb8-44c8-a917-57927947596d': 'AUDIT',
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc': 'AUDIT',
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b': 'AUDIT',
        '01443614-cd74-433a-b99e-2ecdc07bfc25': 'DISABLED',
        'c1db55ab-c21a-4637-bb3f-a12568109d35': 'BLOCK',
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0': 'BLOCK',
        'd1e49aac-8f56-4280-b9ba-993a6d77406c': 'AUDIT',
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': 'AUDIT',
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb': 'AUDIT',
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': 'AUDIT'
      },
      network_protection_mode: 'AUDIT',
      controlled_folder_access: 'DISABLED'
    }
  };

  let currentTab = 'policies';
  let editingPolicyId = null;
  let groupsList = [];

  function modeBadge(mode) {
    if (!mode || mode === 'DISABLED') return '<span style="background:#6b7280;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;">DISABLED</span>';
    if (mode === 'AUDIT') return '<span style="background:#3b82f6;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;">AUDIT</span>';
    if (mode === 'BLOCK') return '<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;">BLOCK</span>';
    if (mode === 'UNKNOWN') return '<span style="background:#9ca3af;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;">UNKNOWN</span>';
    return `<span style="background:#6b7280;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;">${mode}</span>`;
  }

  function actionBadge(action) {
    if (action === 'BLOCKED' || action === 'NETWORK_BLOCKED') return '🚫 BLOCKED';
    return '👁️ AUDITED';
  }

  async function loadData() {
    const container = document.getElementById('view-asr');
    if (!container) return;

    let stats = { total_policies: 0, block_mode_count: 0, audit_mode_count: 0, events_today: 0, devices_covered: 0 };
    try {
      if (window.FleetAPI) stats = await window.FleetAPI.getASRStats();
    } catch (e) {}

    try {
      if (window.FleetAPI) {
        const grpData = await window.FleetAPI.getGroups();
        groupsList = Array.isArray(grpData) ? grpData : (grpData.groups || []);
      }
    } catch (e) {}

    container.innerHTML = `
      <div class="intune-blade-header">
        <div class="intune-breadcrumb">Home &gt; Endpoint security | Attack surface reduction</div>
        <div class="intune-title-row">
          <div class="intune-title-icon">🛡️</div>
          <div>
            <h1 class="intune-blade-title">Attack surface reduction</h1>
            <p class="intune-blade-subtitle">Manage ASR rules, exploit protection, network protection, and controlled folder access policies</p>
          </div>
        </div>
      </div>

      <div class="intune-command-bar">
        <button class="intune-cmd-btn primary" onclick="window.ASRTable.openCreateModal()">
          <span class="cmd-icon">➕</span> Create policy
        </button>
        <button class="intune-cmd-btn" onclick="window.ASRTable.refresh()">
          <span class="cmd-icon">🔄</span> Refresh
        </button>
      </div>

      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0;">
        <div class="intune-kpi-card"><div class="kpi-val">${stats.total_policies}</div><div class="kpi-lbl">🛡️ ASR Policies</div></div>
        <div class="intune-kpi-card"><div class="kpi-val" style="color:#ef4444;">${stats.block_mode_count}</div><div class="kpi-lbl">🚫 Block Mode Rules</div></div>
        <div class="intune-kpi-card"><div class="kpi-val" style="color:#f59e0b;">${stats.events_today}</div><div class="kpi-lbl">👁️ Events Today</div></div>
        <div class="intune-kpi-card"><div class="kpi-val" style="color:#10b981;">${stats.devices_covered}</div><div class="kpi-lbl">📱 Devices Covered</div></div>
      </div>

      <div class="intune-tabs" style="margin-bottom:16px;">
        <button class="intune-tab ${currentTab === 'policies' ? 'active' : ''}" onclick="window.ASRTable.setTab('policies')">ASR Rules</button>
        <button class="intune-tab ${currentTab === 'events' ? 'active' : ''}" onclick="window.ASRTable.setTab('events')">Audit &amp; Block Events</button>
        <button class="intune-tab ${currentTab === 'posture' ? 'active' : ''}" onclick="window.ASRTable.setTab('posture')">Device Posture</button>
      </div>

      <div id="asr-tab-content">
        <div style="color:#9ca3af;padding:20px;text-align:center;">Loading...</div>
      </div>

      <div id="asr-modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:9999;overflow-y:auto;">
        <div style="background:#1e2533;border-radius:8px;max-width:860px;margin:40px auto;padding:24px;color:#e2e8f0;">
          <div id="asr-modal-body"></div>
        </div>
      </div>
    `;

    renderTabContent();
  }

  async function renderTabContent() {
    const el = document.getElementById('asr-tab-content');
    if (!el) return;
    if (currentTab === 'policies') await renderPoliciesTab(el);
    else if (currentTab === 'events') await renderEventsTab(el);
    else if (currentTab === 'posture') await renderPostureTab(el);
  }

  async function renderPoliciesTab(el) {
    let policies = [];
    try {
      if (window.FleetAPI) {
        const d = await window.FleetAPI.getASRPolicies();
        policies = d.policies || [];
      }
    } catch (e) {}

    if (!policies.length) {
      el.innerHTML = '<div style="text-align:center;padding:40px;color:#9ca3af;">No ASR policies configured. Click <b>Create policy</b> to get started.</div>';
      return;
    }

    el.innerHTML = `
      <table class="intune-table">
        <thead><tr>
          <th>Name</th><th>Group Target</th><th>Network Protection</th><th>CFA Mode</th><th>Rules</th><th>Actions</th>
        </tr></thead>
        <tbody>
          ${policies.map(p => {
            const rules = p.asr_rules || {};
            const ruleCount = Object.keys(rules).length;
            const blockCount = Object.values(rules).filter(v => v === 'BLOCK').length;
            return `<tr>
              <td><strong>${escHtml(p.name)}</strong>${p.description ? `<br><small style="color:#9ca3af;">${escHtml(p.description.substring(0, 60))}${p.description.length > 60 ? '...' : ''}</small>` : ''}</td>
              <td>${escHtml(p.target_group_name || p.target_group_id || 'grp-all')}</td>
              <td>${modeBadge(p.network_protection_mode)}</td>
              <td>${modeBadge(p.controlled_folder_access)}</td>
              <td><span style="font-size:12px;">${ruleCount} rules (${blockCount} BLOCK)</span></td>
              <td>
                <button class="intune-link-btn" onclick="window.ASRTable.editPolicy('${escHtml(p.id)}')">Edit</button>
                <button class="intune-link-btn" style="color:#ef4444;" onclick="window.ASRTable.deletePolicy('${escHtml(p.id)}','${escHtml(p.name)}')">Delete</button>
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>`;
  }

  async function renderEventsTab(el) {
    let events = [], count = 0;
    try {
      if (window.FleetAPI) {
        const d = await window.FleetAPI.getASREvents({ limit: 100 });
        events = d.events || [];
        count = d.count || 0;
      }
    } catch (e) {}

    if (!events.length) {
      el.innerHTML = '<div style="text-align:center;padding:40px;color:#9ca3af;">No ASR events reported. Events appear here when Windows Defender reports ASR blocks or audits.</div>';
      return;
    }

    el.innerHTML = `
      <p style="color:#9ca3af;font-size:12px;margin-bottom:8px;">Showing ${events.length} of ${count} total events</p>
      <table class="intune-table">
        <thead><tr>
          <th>Device</th><th>Action</th><th>Rule</th><th>Process</th><th>Target Path</th><th>Occurred</th>
        </tr></thead>
        <tbody>
          ${events.map(e => `<tr>
            <td>${escHtml(e.hostname || e.device_id)}</td>
            <td>${actionBadge(e.action)}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(e.rule_name || e.rule_id || '')}">${escHtml((e.rule_name || e.rule_id || 'Unknown').substring(0, 40))}</td>
            <td style="font-family:monospace;font-size:11px;">${escHtml(e.process_name || '')}</td>
            <td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="${escHtml(e.target_path || '')}">${escHtml((e.target_path || '').substring(0, 40))}</td>
            <td style="font-size:11px;">${e.occurred_at ? new Date(e.occurred_at).toLocaleString() : new Date(e.created_at).toLocaleString()}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }

  async function renderPostureTab(el) {
    let devices = [];
    try {
      if (window.FleetAPI) {
        const d = await window.FleetAPI.getDevices();
        devices = Array.isArray(d) ? d : (d.devices || []);
      }
    } catch (e) {}

    if (!devices.length) {
      el.innerHTML = '<div style="text-align:center;padding:40px;color:#9ca3af;">No devices enrolled.</div>';
      return;
    }

    const postures = await Promise.all(devices.slice(0, 20).map(async dev => {
      try {
        if (window.FleetAPI) return { device: dev, posture: await window.FleetAPI.getDeviceASRStatus(dev.id) };
      } catch (e) {}
      return { device: dev, posture: null };
    }));

    el.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;">
      ${postures.map(({ device, posture }) => {
        const st = posture?.status;
        return `<div style="background:#252d3d;border-radius:8px;padding:16px;border:1px solid #374151;">
          <div style="font-weight:600;margin-bottom:8px;">💻 ${escHtml(device.friendly_name || device.hostname)}</div>
          <div style="font-size:12px;color:#9ca3af;margin-bottom:8px;">${escHtml(device.hostname)}</div>
          ${st ? `
            <div style="margin:4px 0;">Policy: <strong>${escHtml(st.policy_name || st.policy_id || 'Unknown')}</strong></div>
            <div style="margin:4px 0;">Network Protection: ${modeBadge(st.network_protection_mode)}</div>
            <div style="margin:4px 0;">CFA: ${modeBadge(st.controlled_folder_access)}</div>
            <div style="margin:4px 0;">Exploit Protection: ${st.exploit_protection_applied ? '✅ Applied' : '❌ Not applied'}</div>
            <div style="margin:4px 0;font-size:11px;color:#9ca3af;">Events today: ${posture.events_today || 0}</div>
          ` : `<div style="color:#6b7280;font-size:12px;">No posture data reported</div>`}
        </div>`;
      }).join('')}
    </div>`;
  }

  function openCreateModal() {
    editingPolicyId = null;
    renderPolicyModal(null);
  }

  async function editPolicy(id) {
    editingPolicyId = id;
    let policy = null;
    try {
      if (window.FleetAPI) policy = await window.FleetAPI.getASRPolicy(id);
    } catch (e) {}
    renderPolicyModal(policy);
  }

  function renderPolicyModal(policy) {
    const modal = document.getElementById('asr-modal');
    const body = document.getElementById('asr-modal-body');
    if (!modal || !body) return;

    const rules = policy?.asr_rules || {};
    const groupOptions = groupsList.map(g => `<option value="${escHtml(g.id)}" ${(policy?.target_group_id || 'grp-all') === g.id ? 'selected' : ''}>${escHtml(g.name)}</option>`).join('');

    body.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <h2 style="margin:0;">${policy ? 'Edit ASR Policy' : 'Create ASR Policy'}</h2>
        <button onclick="window.ASRTable.closeModal()" style="background:none;border:none;color:#9ca3af;font-size:20px;cursor:pointer;">✕</button>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
        <div>
          <label class="intune-label">Policy Name *</label>
          <input class="intune-input" id="asr-name" type="text" value="${escHtml(policy?.name || '')}" placeholder="e.g. Windows 11 ASR Baseline">
        </div>
        <div>
          <label class="intune-label">Target Group</label>
          <select class="intune-input" id="asr-group">${groupOptions}</select>
        </div>
        <div>
          <label class="intune-label">Network Protection</label>
          <select class="intune-input" id="asr-np">
            ${['DISABLED','AUDIT','BLOCK'].map(m => `<option value="${m}" ${(policy?.network_protection_mode || 'AUDIT') === m ? 'selected' : ''}>${m}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="intune-label">Controlled Folder Access</label>
          <select class="intune-input" id="asr-cfa">
            ${['DISABLED','AUDIT','BLOCK','BLOCK_DISK_MOD_ONLY','AUDIT_DISK_MOD_ONLY'].map(m => `<option value="${m}" ${(policy?.controlled_folder_access || 'DISABLED') === m ? 'selected' : ''}>${m}</option>`).join('')}
          </select>
        </div>
      </div>

      <div>
        <label class="intune-label">Description</label>
        <textarea class="intune-input" id="asr-desc" rows="2" style="resize:vertical;">${escHtml(policy?.description || '')}</textarea>
      </div>

      <div style="margin:16px 0;">
        <label class="intune-label">Enterprise Presets</label>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          ${Object.entries(ASR_PRESETS).map(([key, preset]) =>
            `<button class="intune-cmd-btn" onclick="window.ASRTable.applyPreset('${key}')">${preset.label}</button>`
          ).join('')}
        </div>
      </div>

      <div>
        <label class="intune-label">ASR Rules Configuration</label>
        <div style="max-height:300px;overflow-y:auto;border:1px solid #374151;border-radius:4px;">
          <table class="intune-table" style="margin:0;">
            <thead><tr><th>Rule</th><th>Mode</th></tr></thead>
            <tbody>
              ${Object.entries(ASR_RULE_NAMES).map(([id, name]) => `<tr>
                <td style="font-size:12px;">${escHtml(name)}</td>
                <td>
                  <select class="intune-input" id="asr-rule-${id}" style="padding:2px 8px;font-size:11px;">
                    ${['DISABLED','AUDIT','BLOCK'].map(m =>
                      `<option value="${m}" ${(rules[id] || 'AUDIT') === m ? 'selected' : ''}>${m}</option>`
                    ).join('')}
                  </select>
                </td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <div style="display:flex;gap:8px;margin-top:16px;justify-content:flex-end;">
        <button class="intune-cmd-btn" onclick="window.ASRTable.closeModal()">Cancel</button>
        <button class="intune-cmd-btn primary" onclick="window.ASRTable.savePolicy()">
          ${policy ? 'Save changes' : 'Create policy'}
        </button>
      </div>
    `;

    modal.style.display = 'block';
  }

  function applyPreset(key) {
    const preset = ASR_PRESETS[key];
    if (!preset) return;
    const npSel = document.getElementById('asr-np');
    const cfaSel = document.getElementById('asr-cfa');
    if (npSel) npSel.value = preset.network_protection_mode;
    if (cfaSel) cfaSel.value = preset.controlled_folder_access;
    for (const [ruleId, mode] of Object.entries(preset.rules)) {
      const sel = document.getElementById(`asr-rule-${ruleId}`);
      if (sel) sel.value = mode;
    }
  }

  async function savePolicy() {
    const name = document.getElementById('asr-name')?.value.trim();
    if (!name) { alert('Policy name is required'); return; }

    const asr_rules = {};
    for (const ruleId of Object.keys(ASR_RULE_NAMES)) {
      const sel = document.getElementById(`asr-rule-${ruleId}`);
      if (sel) asr_rules[ruleId] = sel.value;
    }

    const data = {
      name,
      description: document.getElementById('asr-desc')?.value.trim() || '',
      target_group_id: document.getElementById('asr-group')?.value || 'grp-all',
      network_protection_mode: document.getElementById('asr-np')?.value || 'AUDIT',
      controlled_folder_access: document.getElementById('asr-cfa')?.value || 'DISABLED',
      asr_rules,
      enabled: true
    };

    try {
      if (editingPolicyId) {
        await window.FleetAPI.updateASRPolicy(editingPolicyId, data);
      } else {
        await window.FleetAPI.createASRPolicy(data);
      }
      closeModal();
      loadData();
    } catch (err) {
      alert('Error: ' + (err.message || 'Failed to save policy'));
    }
  }

  async function deletePolicy(id, name) {
    if (!confirm(`Delete ASR policy "${name}"? This cannot be undone.`)) return;
    try {
      await window.FleetAPI.deleteASRPolicy(id);
      loadData();
    } catch (err) {
      alert('Error: ' + (err.message || 'Failed to delete policy'));
    }
  }

  function closeModal() {
    const modal = document.getElementById('asr-modal');
    if (modal) modal.style.display = 'none';
  }

  function setTab(tab) {
    currentTab = tab;
    loadData();
  }

  function escHtml(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  window.ASRTable = {
    init: loadData,
    refresh: loadData,
    setTab,
    openCreateModal,
    editPolicy,
    deletePolicy,
    savePolicy,
    closeModal,
    applyPreset
  };
})();
