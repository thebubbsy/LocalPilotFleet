/**
 * LocalPilot Fleet — USB & Peripheral Device Control Blade
 * Removable storage read-only/block policies, hardware whitelist (VID/PID/Serial), and forensic connection audit streams.
 */

function renderPeripheralControlBlade() {
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-800/80 p-5 rounded-xl border border-slate-700/60 shadow-lg backdrop-blur-md">
        <div>
          <div class="flex items-center gap-3">
            <span class="p-2.5 bg-amber-500/20 text-amber-400 rounded-lg text-2xl border border-amber-500/30">🔌</span>
            <div>
              <h2 class="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                USB &amp; Peripheral Device Control
                <span class="text-xs px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">Hardware Protection</span>
              </h2>
              <p class="text-sm text-slate-400 mt-0.5">Removable mass storage access restrictions, Bluetooth tethering controls &amp; hardware whitelist exceptions</p>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="btn-peripheral-refresh" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm font-medium transition flex items-center gap-1.5 border border-slate-600">
            <span>🔄</span> Refresh
          </button>
          <button id="btn-peripheral-new-policy" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-amber-500/20">
            <span>🛡️</span> New USB Policy
          </button>
          <button id="btn-peripheral-new-exception" class="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-1.5 shadow-md hover:shadow-emerald-500/20">
            <span>➕</span> Whitelist Device
          </button>
        </div>
      </div>

      <!-- KPI Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" id="peripheral-kpis">
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Policies</p>
            <span class="p-1.5 bg-amber-500/20 text-amber-400 rounded-md text-sm">🛡️</span>
          </div>
          <p class="text-2xl font-bold text-white mt-2" id="kpi-periph-policies">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Hardware Whitelist</p>
            <span class="p-1.5 bg-emerald-500/20 text-emerald-400 rounded-md text-sm">🔑</span>
          </div>
          <p class="text-2xl font-bold text-emerald-400 mt-2" id="kpi-periph-exceptions">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Blocked Writes</p>
            <span class="p-1.5 bg-rose-500/20 text-rose-400 rounded-md text-sm">🚫</span>
          </div>
          <p class="text-2xl font-bold text-rose-400 mt-2" id="kpi-periph-blocked">-</p>
        </div>
        <div class="bg-slate-800/60 p-4 rounded-xl border border-slate-700/50 shadow">
          <div class="flex justify-between items-start">
            <p class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Connects</p>
            <span class="p-1.5 bg-blue-500/20 text-blue-400 rounded-md text-sm">🔌</span>
          </div>
          <p class="text-2xl font-bold text-blue-400 mt-2" id="kpi-periph-connects">-</p>
        </div>
      </div>

      <!-- Main Layout: Policies (2 cols) & Whitelist (1 col) -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Policies Table (2 cols) -->
        <div class="lg:col-span-2 bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📋</span> Peripheral Device Policies
            </h3>
            <span class="text-xs text-slate-400" id="periph-policy-count">0 configured</span>
          </div>
          <div class="overflow-x-auto flex-1">
            <table class="w-full text-left text-sm text-slate-300">
              <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider">
                <tr>
                  <th class="px-4 py-3">Policy Name</th>
                  <th class="px-4 py-3">Removable Storage</th>
                  <th class="px-4 py-3">Bluetooth</th>
                  <th class="px-4 py-3">Printers</th>
                  <th class="px-4 py-3">Scope</th>
                  <th class="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="periph-policies-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
                <tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">Loading policies...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Hardware Whitelist Exceptions (1 col) -->
        <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden flex flex-col">
          <div class="p-4 border-b border-slate-700/60 flex items-center justify-between">
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>🔑</span> Hardware Exceptions (VID/PID/SN)
            </h3>
            <span class="text-xs text-slate-400" id="periph-exception-count">0 rules</span>
          </div>
          <div class="overflow-y-auto max-h-[380px] p-3 space-y-2.5" id="periph-exceptions-list">
            <div class="text-center text-slate-500 py-6 text-sm">Loading exceptions...</div>
          </div>
        </div>
      </div>

      <!-- Live Peripheral Audit Stream -->
      <div class="bg-slate-800/60 rounded-xl border border-slate-700/50 shadow overflow-hidden">
        <div class="p-4 border-b border-slate-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 class="font-semibold text-white flex items-center gap-2">
              <span>📡</span> Live Peripheral Connection &amp; Write Interception Log
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">Forensic tracking of USB attach/detach, read-only enforcement, and blocked write attempts</p>
          </div>
          <div class="flex items-center gap-2">
            <input type="text" id="periph-filter-query" placeholder="Filter device, user or event..." class="px-2.5 py-1 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 focus:outline-none focus:border-amber-500">
          </div>
        </div>
        <div class="overflow-x-auto max-h-96">
          <table class="w-full text-left text-sm text-slate-300">
            <thead class="bg-slate-900/50 text-xs uppercase text-slate-400 tracking-wider sticky top-0 backdrop-blur-sm">
              <tr>
                <th class="px-4 py-3">Time</th>
                <th class="px-4 py-3">Action</th>
                <th class="px-4 py-3">Event Type</th>
                <th class="px-4 py-3">Device Name / Hardware ID</th>
                <th class="px-4 py-3">Process / Target File</th>
                <th class="px-4 py-3">User</th>
                <th class="px-4 py-3">Node ID</th>
              </tr>
            </thead>
            <tbody id="periph-events-tbody" class="divide-y divide-slate-700/40 font-mono text-xs">
              <tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No events logged yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

async function loadPeripheralControlData() {
  try {
    const [statsRes, polRes, excRes, evtRes] = await Promise.all([
      fetch('/api/v1/fleet/peripheral-control/stats', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/peripheral-control/policies', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/peripheral-control/exceptions', { credentials: 'same-origin' }),
      fetch('/api/v1/fleet/peripheral-control/events?limit=50', { credentials: 'same-origin' })
    ]);

    if (statsRes.ok) {
      const stats = await statsRes.json();
      document.getElementById('kpi-periph-policies').textContent = stats.activePolicies ?? 0;
      document.getElementById('kpi-periph-exceptions').textContent = stats.activeExceptions ?? 0;
      document.getElementById('kpi-periph-blocked').textContent = stats.blockedWrites ?? 0;
      document.getElementById('kpi-periph-connects').textContent = stats.usbAttaches ?? 0;
    }

    if (polRes.ok) {
      const policies = await polRes.json();
      renderPeripheralPolicies(policies);
    }

    if (excRes.ok) {
      const exceptions = await excRes.json();
      renderPeripheralExceptions(exceptions);
    }

    if (evtRes.ok) {
      const data = await evtRes.json();
      renderPeripheralEvents(data.events || []);
    }
  } catch (err) {
    console.error('Error loading peripheral control data:', err);
  }
}

function renderPeripheralPolicies(policies) {
  const tbody = document.getElementById('periph-policies-tbody');
  const countBadge = document.getElementById('periph-policy-count');
  if (countBadge) countBadge.textContent = `${policies.length} configured`;
  if (!tbody) return;

  if (!policies || policies.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500 font-sans">No USB control policies configured.</td></tr>';
    return;
  }

  tbody.innerHTML = policies.map(p => {
    const storageBadge = p.removable_storage_access === 'BLOCK'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (p.removable_storage_access === 'READ_ONLY' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30');

    const btBadge = p.bluetooth_mode === 'DISABLED'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (p.bluetooth_mode === 'RESTRICTED' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-slate-700 text-slate-300 border-slate-600');

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-3">
          <div class="font-bold font-sans text-white text-sm">${escapeHtml(p.name)}</div>
          <div class="text-[11px] text-slate-400 font-sans truncate max-w-xs">${escapeHtml(p.description || '')}</div>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs border ${storageBadge}">${escapeHtml(p.removable_storage_access)}</span>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs border ${btBadge}">${escapeHtml(p.bluetooth_mode)}</span>
        </td>
        <td class="px-4 py-3">
          <span class="px-2 py-0.5 rounded text-xs bg-slate-700/60 border border-slate-600 text-slate-300">${escapeHtml(p.printer_protection_mode)}</span>
        </td>
        <td class="px-4 py-3 font-sans">
          <span class="px-2 py-0.5 rounded text-xs bg-slate-700/60 border border-slate-600 text-slate-300">${escapeHtml(p.target_scope)}</span>
        </td>
        <td class="px-4 py-3 text-right">
          <button class="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-xs transition mr-1" onclick="viewPeripheralScript('${escapeHtml(p.id)}')">
            <span>📜</span> Script
          </button>
          <button class="px-2 py-1 bg-rose-900/30 hover:bg-rose-900/60 text-rose-300 rounded text-xs transition border border-rose-700/30" onclick="deletePeripheralPolicy('${escapeHtml(p.id)}')">
            <span>🗑️</span>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderPeripheralExceptions(exceptions) {
  const container = document.getElementById('periph-exceptions-list');
  const countBadge = document.getElementById('periph-exception-count');
  if (countBadge) countBadge.textContent = `${exceptions.length} rules`;
  if (!container) return;

  if (!exceptions || exceptions.length === 0) {
    container.innerHTML = '<div class="text-center text-slate-500 py-6 text-sm">No hardware whitelist exceptions.</div>';
    return;
  }

  container.innerHTML = exceptions.map(exc => {
    const actBadge = exc.action === 'ALLOW'
      ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
      : (exc.action === 'AUDIT_ONLY' ? 'text-amber-400 bg-amber-500/10 border-amber-500/30' : 'text-rose-400 bg-rose-500/10 border-rose-500/30');

    return `
      <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-700/60 flex items-center justify-between text-xs">
        <div class="min-w-0 flex-1 pr-2">
          <div class="flex items-center gap-1.5 mb-1">
            <span class="px-1.5 py-0.5 rounded text-[10px] uppercase font-bold border ${actBadge}">${escapeHtml(exc.action)}</span>
            <span class="font-sans font-semibold text-white truncate">${escapeHtml(exc.friendly_name)}</span>
          </div>
          <div class="font-mono text-slate-300 text-[11px]">
            VID: ${escapeHtml(exc.vendor_id || '*')} | PID: ${escapeHtml(exc.product_id || '*')}
          </div>
          <div class="text-[10px] text-slate-400 mt-0.5 truncate font-mono">
            SN: ${escapeHtml(exc.serial_number || 'Any')}
          </div>
        </div>
        <button class="p-1 text-slate-400 hover:text-rose-400 transition" onclick="deletePeripheralException('${escapeHtml(exc.id)}')">
          <span>🗑️</span>
        </button>
      </div>
    `;
  }).join('');
}

function renderPeripheralEvents(events) {
  const tbody = document.getElementById('periph-events-tbody');
  if (!tbody) return;

  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No events logged yet.</td></tr>';
    return;
  }

  tbody.innerHTML = events.map(evt => {
    const actBadge = evt.action_taken === 'BLOCKED'
      ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
      : (evt.action_taken === 'AUDITED' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30');

    const d = new Date(evt.timestamp);
    const timeStr = isNaN(d.getTime()) ? evt.timestamp : d.toLocaleTimeString();

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="px-4 py-2.5 text-slate-400">${timeStr}</td>
        <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-xs border ${actBadge}">${escapeHtml(evt.action_taken)}</span></td>
        <td class="px-4 py-2.5 text-slate-300 font-sans font-medium">${escapeHtml(evt.event_type)}</td>
        <td class="px-4 py-2.5">
          <div class="text-white font-medium truncate max-w-xs" title="${escapeHtml(evt.device_name)}">${escapeHtml(evt.device_name)}</div>
          <div class="text-[10px] text-slate-500 truncate max-w-xs font-mono">${escapeHtml(evt.hardware_id || '')}</div>
        </td>
        <td class="px-4 py-2.5 text-slate-300 truncate max-w-xs font-mono" title="${escapeHtml(evt.file_path || evt.process_name)}">
          ${escapeHtml(evt.file_path || evt.process_name)}
        </td>
        <td class="px-4 py-2.5 text-slate-400 font-sans">${escapeHtml(evt.username || 'System')}</td>
        <td class="px-4 py-2.5 text-slate-500 truncate max-w-[80px] font-mono">${escapeHtml(evt.device_id.substring(0, 8))}...</td>
      </tr>
    `;
  }).join('');
}

function initPeripheralControlBlade() {
  const refreshBtn = document.getElementById('btn-peripheral-refresh');
  if (refreshBtn) refreshBtn.addEventListener('click', loadPeripheralControlData);

  const newPolicyBtn = document.getElementById('btn-peripheral-new-policy');
  if (newPolicyBtn) {
    newPolicyBtn.addEventListener('click', () => {
      const name = prompt('Policy Name:', 'Executive USB Read-Only Baseline');
      if (!name) return;
      const mode = prompt('Removable Storage Access (READ_ONLY, BLOCK, ALLOW):', 'READ_ONLY');
      if (!mode) return;

      fetch('/api/v1/fleet/peripheral-control/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name,
          removable_storage_access: mode,
          bluetooth_mode: 'RESTRICTED',
          printer_protection_mode: 'AUDIT',
          audit_level: 'DETAILED'
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadPeripheralControlData());
    });
  }

  const newExceptionBtn = document.getElementById('btn-peripheral-new-exception');
  if (newExceptionBtn) {
    newExceptionBtn.addEventListener('click', () => {
      const name = prompt('Hardware Friendly Name (e.g. IT Department SanDisk):', 'SanDisk Extreme Pro 128GB');
      if (!name) return;
      const vid = prompt('Vendor ID (VID 4 hex digits, e.g. 0781):', '0781');
      if (!vid) return;
      const pid = prompt('Product ID (PID 4 hex digits, e.g. 5583):', '5583');
      if (!pid) return;

      fetch('/api/v1/fleet/peripheral-control/exceptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          friendly_name: name,
          vendor_id: vid,
          product_id: pid,
          action: 'ALLOW'
        }),
        credentials: 'same-origin'
      }).then(r => r.json()).then(() => loadPeripheralControlData());
    });
  }

  const filterInput = document.getElementById('periph-filter-query');
  if (filterInput) {
    filterInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#periph-events-tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }

  loadPeripheralControlData();
}

async function deletePeripheralPolicy(id) {
  if (!confirm('Are you sure you want to delete this USB control policy?')) return;
  await fetch(`/api/v1/fleet/peripheral-control/policies/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadPeripheralControlData();
}

async function deletePeripheralException(id) {
  if (!confirm('Delete this hardware whitelist exception?')) return;
  await fetch(`/api/v1/fleet/peripheral-control/exceptions/${id}`, { method: 'DELETE', credentials: 'same-origin' });
  loadPeripheralControlData();
}

async function viewPeripheralScript(id) {
  try {
    const res = await fetch('/api/v1/fleet/peripheral-control/script/default', { credentials: 'same-origin' });
    if (res.ok) {
      const script = await res.text();
      alert('Windows Defender USB Control Configuration Script:\n\n' + script.substring(0, 500) + '...');
    }
  } catch (e) {
    console.error(e);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.renderPeripheralControlBlade = renderPeripheralControlBlade;
window.initPeripheralControlBlade = initPeripheralControlBlade;
window.loadPeripheralControlData = loadPeripheralControlData;
window.deletePeripheralPolicy = deletePeripheralPolicy;
window.deletePeripheralException = deletePeripheralException;
window.viewPeripheralScript = viewPeripheralScript;

window.PeripheralControlTable = {
  async render() {
    const container = document.getElementById('tab-peripheral-control');
    if (!container) return;
    container.innerHTML = renderPeripheralControlBlade();
    initPeripheralControlBlade();
  }
};
