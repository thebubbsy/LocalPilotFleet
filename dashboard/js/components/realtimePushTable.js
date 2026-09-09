/**
 * LocalPilot Fleet — Real-Time Push Transport Dashboard Blade
 * dashboard/js/components/realtimePushTable.js
 *
 * Dimension 2: Transport, Real-Time Push & Scalability
 * Displays active WebSocket / SSE persistent channels, live message delivery ledger,
 * sub-3-second SLA metrics, and emergency instant dispatch console.
 */

window.RealtimePushTable = {
  currentTab: 'channels',
  stats: null,
  channels: [],
  messages: [],
  devices: [],
  groups: [],

  async render() {
    const container = document.getElementById('tab-push');
    if (!container) return;

    container.innerHTML = `
      <div class="blade-header" style="margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h2 style="margin: 0; font-size: 1.4rem; display: flex; align-items: center; gap: 0.5rem;">
            <span>⚡</span> Real-Time Push Transport & Scalability
            <span class="badge badge-success" style="font-size: 0.75rem; padding: 2px 8px; border-radius: 9999px;">Dimension 2</span>
          </h2>
          <p class="text-muted" style="margin: 0.25rem 0 0 0; font-size: 0.85rem;">
            Persistent bi-directional push streaming (WebSocket / SSE Duplex) with sub-3-second latency SLA for emergency wipe, lock, isolate, and instant command dispatch.
          </p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary btn-sm" onclick="RealtimePushTable.refresh()">
            <span>🔄</span> Refresh
          </button>
          <button class="btn btn-primary btn-sm" onclick="RealtimePushTable.openInstantDispatchModal()">
            <span>⚡</span> Instant Push Dispatch
          </button>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div class="kpi-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Active Channels</div>
          <div class="kpi-value" id="kpi-push-channels" style="font-size: 1.6rem; font-weight: 700; color: #38bdf8; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" id="kpi-push-channels-sub" style="font-size: 0.75rem; color: #64748b;">Persistent Sockets / Streams</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Sub-3-Second SLA</div>
          <div class="kpi-value" id="kpi-push-sla" style="font-size: 1.6rem; font-weight: 700; color: #10b981; margin: 0.25rem 0;">--%</div>
          <div class="kpi-subtitle" style="font-size: 0.75rem; color: #64748b;">Target: &ge; 99.0% &le; 3000ms</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Dispatched Messages</div>
          <div class="kpi-value" id="kpi-push-messages" style="font-size: 1.6rem; font-weight: 700; color: #f59e0b; margin: 0.25rem 0;">--</div>
          <div class="kpi-subtitle" id="kpi-push-messages-sub" style="font-size: 0.75rem; color: #64748b;">100% Delivery Ledger</div>
        </div>
        <div class="kpi-card" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1rem;">
          <div class="kpi-label" style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Mean Latency</div>
          <div class="kpi-value" id="kpi-push-latency" style="font-size: 1.6rem; font-weight: 700; color: #a855f7; margin: 0.25rem 0;">-- ms</div>
          <div class="kpi-subtitle" id="kpi-push-latency-sub" style="font-size: 0.75rem; color: #64748b;">Round-Trip Delivery Latency</div>
        </div>
      </div>

      <!-- Sub-Tabs Navigation -->
      <div class="subtabs" style="display: flex; gap: 0.5rem; border-bottom: 1px solid var(--border-color, #334155); margin-bottom: 1rem;">
        <button class="tab-btn active" id="subtab-btn-push-channels" onclick="RealtimePushTable.switchSubTab('channels')" style="background: none; border: none; padding: 0.5rem 1rem; color: #94a3b8; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 500;">
          🔌 Active Sockets & Channels
        </button>
        <button class="tab-btn" id="subtab-btn-push-messages" onclick="RealtimePushTable.switchSubTab('messages')" style="background: none; border: none; padding: 0.5rem 1rem; color: #94a3b8; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 500;">
          📜 Push Delivery Ledger
        </button>
        <button class="tab-btn" id="subtab-btn-push-console" onclick="RealtimePushTable.switchSubTab('console')" style="background: none; border: none; padding: 0.5rem 1rem; color: #94a3b8; cursor: pointer; border-bottom: 2px solid transparent; font-weight: 500;">
          ⚡ Emergency Instant Dispatch Console
        </button>
      </div>

      <!-- Subtab 1: Channels -->
      <div id="subtab-content-push-channels" class="subtab-content">
        <div class="table-container" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
          <table class="data-table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
              <tr style="background: rgba(15, 23, 42, 0.6); text-align: left; border-bottom: 1px solid #334155;">
                <th style="padding: 0.75rem 1rem;">Node / Device</th>
                <th style="padding: 0.75rem 1rem;">Transport</th>
                <th style="padding: 0.75rem 1rem;">Protocol</th>
                <th style="padding: 0.75rem 1rem;">Status</th>
                <th style="padding: 0.75rem 1rem;">Client IP</th>
                <th style="padding: 0.75rem 1rem;">Last Ping</th>
                <th style="padding: 0.75rem 1rem;">Connected Since</th>
                <th style="padding: 0.75rem 1rem;">Actions</th>
              </tr>
            </thead>
            <tbody id="push-channels-tbody">
              <tr><td colspan="8" style="padding: 2rem; text-align: center; color: #64748b;">Loading active channels...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Subtab 2: Messages -->
      <div id="subtab-content-push-messages" class="subtab-content" style="display: none;">
        <div class="table-container" style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
          <table class="data-table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
              <tr style="background: rgba(15, 23, 42, 0.6); text-align: left; border-bottom: 1px solid #334155;">
                <th style="padding: 0.75rem 1rem;">Message ID</th>
                <th style="padding: 0.75rem 1rem;">Target Node</th>
                <th style="padding: 0.75rem 1rem;">Topic</th>
                <th style="padding: 0.75rem 1rem;">Priority</th>
                <th style="padding: 0.75rem 1rem;">Status</th>
                <th style="padding: 0.75rem 1rem;">Delivery Latency</th>
                <th style="padding: 0.75rem 1rem;">Dispatched At</th>
                <th style="padding: 0.75rem 1rem;">Actions</th>
              </tr>
            </thead>
            <tbody id="push-messages-tbody">
              <tr><td colspan="8" style="padding: 2rem; text-align: center; color: #64748b;">Loading message ledger...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Subtab 3: Instant Dispatch Console -->
      <div id="subtab-content-push-console" class="subtab-content" style="display: none;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
          <div style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1.25rem;">
            <h3 style="margin: 0 0 1rem 0; font-size: 1.1rem; display: flex; align-items: center; gap: 0.5rem;">
              <span>🚀</span> Emergency Instant Dispatcher
            </h3>
            
            <div style="margin-bottom: 1rem;">
              <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">Target Scope</label>
              <select id="push-console-target" class="form-control" style="width: 100%; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px;">
                <option value="group:grp-all">🌐 All Enrolled Nodes (grp-all)</option>
                <option value="group:grp-workstations">💻 High-Performance Workstations (grp-workstations)</option>
              </select>
            </div>

            <div style="margin-bottom: 1rem;">
              <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">Command Preset</label>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                <button type="button" class="btn btn-secondary btn-sm" onclick="RealtimePushTable.selectPreset('LOCK')" style="text-align: left; padding: 0.5rem;">
                  🔒 Emergency Lock
                </button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="RealtimePushTable.selectPreset('POLICY_SYNC')" style="text-align: left; padding: 0.5rem;">
                  🔄 Force Policy Sync
                </button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="RealtimePushTable.selectPreset('ISOLATE')" style="text-align: left; padding: 0.5rem;">
                  🛡️ Network Isolation
                </button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="RealtimePushTable.selectPreset('PING')" style="text-align: left; padding: 0.5rem;">
                  ⚡ Low-Latency Ping
                </button>
              </div>
            </div>

            <div style="margin-bottom: 1rem;">
              <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">Topic</label>
              <select id="push-console-topic" class="form-control" style="width: 100%; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px;">
                <option value="LOCK">LOCK (Emergency Session Lock)</option>
                <option value="POLICY_SYNC">POLICY_SYNC (Immediate MDM Evaluation)</option>
                <option value="ISOLATE">ISOLATE (Firewall Network Containment)</option>
                <option value="COMMAND">COMMAND (Sub-3s Cloud Shell Script)</option>
                <option value="WIPE">WIPE (Zero-Trust Cryptographic Wipe)</option>
                <option value="PING">PING (Latency Diagnostic Probe)</option>
              </select>
            </div>

            <div style="margin-bottom: 1rem;">
              <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">Priority</label>
              <select id="push-console-priority" class="form-control" style="width: 100%; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px;">
                <option value="URGENT">URGENT (Immediate Pre-Emption)</option>
                <option value="HIGH" selected>HIGH (Fast Push)</option>
                <option value="NORMAL">NORMAL (Standard)</option>
              </select>
            </div>

            <div style="margin-bottom: 1.25rem;">
              <label style="display: block; font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.25rem;">Payload JSON</label>
              <textarea id="push-console-payload" class="form-control" rows="4" style="width: 100%; padding: 0.5rem; background: #0f172a; border: 1px solid #334155; color: #fff; border-radius: 4px; font-family: monospace; font-size: 0.8rem;">{"action": "REMOTE_LOCK", "reason": "Administrative emergency trigger"}</textarea>
            </div>

            <button class="btn btn-primary" onclick="RealtimePushTable.executeConsoleDispatch()" style="width: 100%; padding: 0.6rem; font-weight: 600;">
              ⚡ Fire Push Message Now (&le; 3s SLA)
            </button>
          </div>

          <!-- Console Output Stream -->
          <div style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 8px; padding: 1.25rem; display: flex; flex-direction: column;">
            <h3 style="margin: 0 0 1rem 0; font-size: 1.1rem; display: flex; align-items: center; justify-content: space-between;">
              <span style="display: flex; align-items: center; gap: 0.5rem;">📡 Dispatch Stream Telemetry</span>
              <span id="push-latency-badge" class="badge badge-success" style="font-size: 0.7rem; display: none;">-- ms roundtrip</span>
            </h3>
            <div id="push-console-log" style="flex: 1; background: #0a0f1d; border: 1px solid #1e293b; border-radius: 4px; padding: 0.75rem; font-family: 'Cascadia Code', Consolas, monospace; font-size: 0.8rem; color: #38bdf8; overflow-y: auto; max-height: 420px; white-space: pre-wrap;">
[Ready] Push Transport Daemon active.
Select target scope and command to broadcast over persistent duplex channel.
            </div>
          </div>
        </div>
      </div>
    `;

    await this.refresh();
  },

  async refresh() {
    try {
      const [statsRes, chanRes, msgRes, devRes, grpRes] = await Promise.all([
        window.FleetAPI.getPushStats(),
        window.FleetAPI.getPushChannels(),
        window.FleetAPI.getPushMessages({ limit: 50 }),
        window.FleetAPI.getDevices(),
        window.FleetAPI.getGroups()
      ]);

      this.stats = statsRes;
      this.channels = chanRes.channels || [];
      this.messages = msgRes.messages || [];
      this.devices = devRes.devices || devRes || [];
      this.groups = grpRes.groups || grpRes || [];

      this.updateKpis();
      this.renderChannels();
      this.renderMessages();
      this.populateTargets();
    } catch (err) {
      console.error('Failed to load push stats:', err);
    }
  },

  updateKpis() {
    if (!this.stats) return;
    document.getElementById('kpi-push-channels').innerText = this.stats.active_channels || 0;
    document.getElementById('kpi-push-channels-sub').innerText = `${this.stats.total_channels || 0} Total Channel Registrations`;
    
    document.getElementById('kpi-push-sla').innerText = `${this.stats.sub_3s_sla_percent || 100.0}%`;
    document.getElementById('kpi-push-messages').innerText = this.stats.total_messages || 0;
    document.getElementById('kpi-push-messages-sub').innerText = `${this.stats.acknowledged_messages || 0} Acknowledged Delivered`;

    document.getElementById('kpi-push-latency').innerText = `${this.stats.mean_latency_ms || 0} ms`;
    document.getElementById('kpi-push-latency-sub').innerText = `Min: ${this.stats.min_latency_ms || 0}ms | Max: ${this.stats.max_latency_ms || 0}ms`;
  },

  switchSubTab(tab) {
    this.currentTab = tab;
    ['channels', 'messages', 'console'].forEach(t => {
      const btn = document.getElementById(`subtab-btn-push-${t}`);
      const content = document.getElementById(`subtab-content-push-${t}`);
      if (btn && content) {
        if (t === tab) {
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

  renderChannels() {
    const tbody = document.getElementById('push-channels-tbody');
    if (!tbody) return;

    if (this.channels.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="padding: 2rem; text-align: center; color: #64748b;">No registered push channels found.</td></tr>';
      return;
    }

    tbody.innerHTML = this.channels.map(c => {
      const statusBadge = c.status === 'ACTIVE'
        ? '<span class="badge badge-success" style="padding: 2px 6px; font-size: 0.75rem;">ACTIVE</span>'
        : '<span class="badge badge-secondary" style="padding: 2px 6px; font-size: 0.75rem;">DISCONNECTED</span>';

      const hostLabel = c.friendly_name ? `${c.friendly_name} (${c.hostname || c.node_id})` : (c.hostname || c.node_id);

      return `
        <tr style="border-bottom: 1px solid #334155;">
          <td style="padding: 0.75rem 1rem; font-weight: 600;">${hostLabel}</td>
          <td style="padding: 0.75rem 1rem;"><code style="background: rgba(56, 189, 248, 0.1); color: #38bdf8; padding: 2px 6px; border-radius: 4px;">${c.transport_type}</code></td>
          <td style="padding: 0.75rem 1rem; color: #94a3b8;">${c.protocol_version}</td>
          <td style="padding: 0.75rem 1rem;">${statusBadge}</td>
          <td style="padding: 0.75rem 1rem; color: #94a3b8;">${c.client_ip || 'Localhost'}</td>
          <td style="padding: 0.75rem 1rem; color: #94a3b8;">${c.last_ping_at || '--'}</td>
          <td style="padding: 0.75rem 1rem; color: #94a3b8;">${c.connected_at || '--'}</td>
          <td style="padding: 0.75rem 1rem;">
            <button class="btn btn-secondary btn-sm" onclick="RealtimePushTable.pingNode('${c.node_id}')" style="padding: 2px 8px; font-size: 0.75rem;">
              ⚡ Ping
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  renderMessages() {
    const tbody = document.getElementById('push-messages-tbody');
    if (!tbody) return;

    if (this.messages.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="padding: 2rem; text-align: center; color: #64748b;">No push messages dispatched yet.</td></tr>';
      return;
    }

    tbody.innerHTML = this.messages.map(m => {
      let statusBadge = '';
      if (m.status === 'ACKNOWLEDGED') statusBadge = '<span class="badge badge-success" style="padding: 2px 6px; font-size: 0.75rem;">ACKNOWLEDGED</span>';
      else if (m.status === 'SENT') statusBadge = '<span class="badge badge-info" style="padding: 2px 6px; font-size: 0.75rem;">SENT</span>';
      else if (m.status === 'QUEUED') statusBadge = '<span class="badge badge-warning" style="padding: 2px 6px; font-size: 0.75rem;">QUEUED</span>';
      else statusBadge = `<span class="badge badge-danger" style="padding: 2px 6px; font-size: 0.75rem;">${m.status}</span>`;

      const priorityColor = m.priority === 'URGENT' ? '#ef4444' : (m.priority === 'HIGH' ? '#f59e0b' : '#38bdf8');
      const latencyStr = m.latency_ms !== null && m.latency_ms !== undefined ? `${m.latency_ms} ms` : '--';

      return `
        <tr style="border-bottom: 1px solid #334155;">
          <td style="padding: 0.75rem 1rem; font-family: monospace; font-size: 0.8rem; color: #94a3b8;">${m.id}</td>
          <td style="padding: 0.75rem 1rem; font-weight: 500;">${m.hostname || m.node_id}</td>
          <td style="padding: 0.75rem 1rem;"><strong>${m.topic}</strong></td>
          <td style="padding: 0.75rem 1rem;"><span style="color: ${priorityColor}; font-weight: 600;">${m.priority}</span></td>
          <td style="padding: 0.75rem 1rem;">${statusBadge}</td>
          <td style="padding: 0.75rem 1rem; font-weight: 600; color: #10b981;">${latencyStr}</td>
          <td style="padding: 0.75rem 1rem; color: #94a3b8; font-size: 0.75rem;">${m.dispatched_at}</td>
          <td style="padding: 0.75rem 1rem;">
            <button class="btn btn-secondary btn-sm" onclick="alert(JSON.stringify(JSON.parse(${JSON.stringify(m.payload_json)}), null, 2))" style="padding: 2px 8px; font-size: 0.75rem;">
              🔍 View Payload
            </button>
          </td>
        </tr>
      `;
    }).join('');
  },

  populateTargets() {
    const sel = document.getElementById('push-console-target');
    if (!sel) return;

    let html = '';
    // Groups
    if (this.groups.length > 0) {
      html += '<optgroup label="Dynamic Device Groups">';
      for (const g of this.groups) {
        html += `<option value="group:${g.id}">👥 ${g.name}</option>`;
      }
      html += '</optgroup>';
    }

    // Individual Nodes
    if (this.devices.length > 0) {
      html += '<optgroup label="Individual Enrolled Nodes">';
      for (const d of this.devices) {
        html += `<option value="node:${d.id}">💻 ${d.friendly_name || d.hostname} (${d.status})</option>`;
      }
      html += '</optgroup>';
    }

    sel.innerHTML = html;
  },

  selectPreset(type) {
    const topicSel = document.getElementById('push-console-topic');
    const payloadText = document.getElementById('push-console-payload');
    const prioritySel = document.getElementById('push-console-priority');

    if (type === 'LOCK') {
      topicSel.value = 'LOCK';
      prioritySel.value = 'URGENT';
      payloadText.value = JSON.stringify({ action: 'REMOTE_LOCK', reason: 'Emergency Executive Screen Lock' }, null, 2);
    } else if (type === 'POLICY_SYNC') {
      topicSel.value = 'POLICY_SYNC';
      prioritySel.value = 'HIGH';
      payloadText.value = JSON.stringify({ action: 'SYNC_MDM', scope: 'FULL_POLICY' }, null, 2);
    } else if (type === 'ISOLATE') {
      topicSel.value = 'ISOLATE';
      prioritySel.value = 'URGENT';
      payloadText.value = JSON.stringify({ action: 'NETWORK_ISOLATE', allow_fleet_traffic: true }, null, 2);
    } else if (type === 'PING') {
      topicSel.value = 'PING';
      prioritySel.value = 'HIGH';
      payloadText.value = JSON.stringify({ probe: 'LATENCY_TEST', timestamp: new Date().toISOString() }, null, 2);
    }
  },

  async pingNode(nodeId) {
    try {
      const startTime = performance.now();
      const res = await window.FleetAPI.dispatchPushMessage({
        node_id: nodeId,
        topic: 'PING',
        priority: 'HIGH',
        payload: { ping: true, timestamp: new Date().toISOString() }
      });
      const roundtrip = Math.round(performance.now() - startTime);
      alert(`⚡ Push Message Dispatched to ${nodeId}!\nStatus: ${res.messages?.[0]?.status}\nAPI Dispatch latency: ${roundtrip} ms`);
      await this.refresh();
    } catch (err) {
      alert(`Failed to dispatch ping: ${err.message}`);
    }
  },

  async executeConsoleDispatch() {
    const targetVal = document.getElementById('push-console-target').value;
    const topic = document.getElementById('push-console-topic').value;
    const priority = document.getElementById('push-console-priority').value;
    const payloadStr = document.getElementById('push-console-payload').value;
    const logBox = document.getElementById('push-console-log');
    const badge = document.getElementById('push-latency-badge');

    let payloadObj = {};
    try {
      payloadObj = JSON.parse(payloadStr);
    } catch (e) {
      alert('Invalid JSON in payload field: ' + e.message);
      return;
    }

    const isGroup = targetVal.startsWith('group:');
    const targetId = targetVal.split(':')[1];

    const startTime = performance.now();
    logBox.innerText += `\n[Dispatched ${new Date().toLocaleTimeString()}] Topic: ${topic} | Target: ${targetVal} | Priority: ${priority}...`;

    try {
      const dispatchData = {
        topic,
        priority,
        payload: payloadObj
      };
      if (isGroup) {
        dispatchData.group_id = targetId;
      } else {
        dispatchData.node_id = targetId;
      }

      const res = await window.FleetAPI.dispatchPushMessage(dispatchData);
      const latencyMs = Math.round((performance.now() - startTime) * 10) / 10;

      badge.style.display = 'inline-block';
      badge.innerText = `${latencyMs} ms API roundtrip`;

      logBox.innerText += `\n[Delivered] Dispatched ${res.dispatched_count} message(s) in ${latencyMs} ms!\n${JSON.stringify(res.messages, null, 2)}`;
      logBox.scrollTop = logBox.scrollHeight;

      await this.refresh();
    } catch (err) {
      logBox.innerText += `\n[ERROR] Dispatch failed: ${err.message}`;
    }
  },

  openInstantDispatchModal() {
    this.switchSubTab('console');
  }
};
