/**
 * LocalPilot Fleet — Device Table Component
 * dashboard/js/components/deviceTable.js
 *
 * Full device inventory table with search, filter, sort, pagination (25/page),
 * and click-to-open Birth Certificate drawer.
 */

(function () {
  'use strict';

  const PAGE_SIZE = 25;

  let _allDevices    = [];
  let _filtered      = [];
  let _currentPage   = 1;
  let _sortField     = 'last_seen_at';
  let _sortDir       = 'desc';
  let _searchTerm    = '';
  let _statusFilter  = '';
  let _routeFilter   = '';

  /* ── Status badge HTML ──────────────────────────────────────────── */
  function statusBadge(status) {
    const map = {
      online:      '<span class="badge badge-online">Online</span>',
      offline:     '<span class="badge badge-offline">Offline</span>',
      drifted:     '<span class="badge badge-drifted">Drifted</span>',
      quarantined: '<span class="badge badge-quarantined">Quarantined</span>'
    };
    return map[status] || `<span class="badge badge-offline">${status}</span>`;
  }

  /* ── Route badge HTML ───────────────────────────────────────────── */
  function routeBadge(route) {
    if (route === 'Cloudflare') return '<span class="badge badge-cloudflare">☁️ Tunnel</span>';
    return '<span class="badge badge-lan">🏠 LAN</span>';
  }

  /* ── Format last seen ───────────────────────────────────────────── */
  function formatLastSeen(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    const now = Date.now();
    const diffMs = now - d.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1)   return 'Just now';
    if (diffMin < 60)  return `${diffMin}m ago`;
    if (diffMin < 1440) return `${Math.floor(diffMin/60)}h ago`;
    return d.toLocaleDateString();
  }

  /* ── Format RAM ─────────────────────────────────────────────────── */
  function formatRam(bytes) {
    if (!bytes) return '—';
    return `${(bytes / 1073741824).toFixed(0)} GB`;
  }

  /* ── Apply search + filters ─────────────────────────────────────── */
  function applyFilters() {
    let src = _allDevices;

    if (_searchTerm) {
      const q = _searchTerm.toLowerCase();
      src = src.filter(d =>
        (d.hostname || '').toLowerCase().includes(q) ||
        (d.friendly_name || '').toLowerCase().includes(q) ||
        (d.ip_address || '').toLowerCase().includes(q) ||
        (d.os_build || '').toLowerCase().includes(q)
      );
    }

    if (_statusFilter) {
      src = src.filter(d => d.status === _statusFilter);
    }

    if (_routeFilter) {
      src = src.filter(d => d.connection_route === _routeFilter);
    }

    // Sort
    src = src.slice().sort((a, b) => {
      let av = a[_sortField];
      let bv = b[_sortField];
      if (av === null || av === undefined) av = '';
      if (bv === null || bv === undefined) bv = '';
      // Numeric comparison
      if (typeof av === 'number' && typeof bv === 'number') {
        return _sortDir === 'asc' ? av - bv : bv - av;
      }
      av = String(av).toLowerCase();
      bv = String(bv).toLowerCase();
      if (av < bv) return _sortDir === 'asc' ? -1 : 1;
      if (av > bv) return _sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    _filtered = src;
    _currentPage = 1;
  }

  /* ── Sort indicator ─────────────────────────────────────────────── */
  function sortIndicator(field) {
    if (_sortField !== field) return ' <span style="opacity:0.3;">↕</span>';
    return _sortDir === 'asc' ? ' ↑' : ' ↓';
  }

  /* ── Render the full devices tab ────────────────────────────────── */
  function renderDeviceTable() {
    const container = document.getElementById('devices-container');
    if (!container) return;

    const start  = (_currentPage - 1) * PAGE_SIZE;
    const end    = start + PAGE_SIZE;
    const page   = _filtered.slice(start, end);
    const total  = _filtered.length;
    const pages  = Math.ceil(total / PAGE_SIZE) || 1;

    container.innerHTML = `
      <div class="page-header">
        <div>
          <div class="page-title">Device Inventory</div>
          <div class="page-subtitle">${total} device${total !== 1 ? 's' : ''} enrolled</div>
        </div>
        <button class="btn btn-ghost btn-sm" id="devices-refresh-btn">🔄 Refresh</button>
      </div>

      <!-- Search & Filter Bar -->
      <div class="search-bar">
        <div class="search-input-wrap">
          <span class="search-icon">🔍</span>
          <input
            class="search-input"
            id="device-search"
            type="text"
            placeholder="Search by hostname, IP, OS build…"
            value="${_searchTerm}"
          >
        </div>
        <select class="filter-select" id="device-status-filter">
          <option value="">All Statuses</option>
          <option value="online"      ${_statusFilter==='online'?'selected':''}>Online</option>
          <option value="offline"     ${_statusFilter==='offline'?'selected':''}>Offline</option>
          <option value="drifted"     ${_statusFilter==='drifted'?'selected':''}>Drifted</option>
          <option value="quarantined" ${_statusFilter==='quarantined'?'selected':''}>Quarantined</option>
        </select>
        <select class="filter-select" id="device-route-filter">
          <option value="">All Routes</option>
          <option value="LAN"        ${_routeFilter==='LAN'?'selected':''}>LAN</option>
          <option value="Cloudflare" ${_routeFilter==='Cloudflare'?'selected':''}>Cloudflare</option>
        </select>
      </div>

      <!-- Device Table -->
      <div class="glass-card">
        <div class="data-table-wrap">
          <table class="data-table" id="device-table">
            <thead>
              <tr>
                <th data-sort="hostname">Hostname${sortIndicator('hostname')}</th>
                <th data-sort="status">Status${sortIndicator('status')}</th>
                <th data-sort="os_build">OS Build${sortIndicator('os_build')}</th>
                <th data-sort="ip_address">IP Address${sortIndicator('ip_address')}</th>
                <th data-sort="connection_route">Route${sortIndicator('connection_route')}</th>
                <th data-sort="total_ram_bytes">RAM${sortIndicator('total_ram_bytes')}</th>
                <th data-sort="last_seen_at">Last Seen${sortIndicator('last_seen_at')}</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="device-tbody">
              ${page.length === 0
                ? `<tr><td colspan="8">
                    <div class="empty-state">
                      <div class="empty-state-icon">🖥️</div>
                      <div class="empty-state-title">No devices found</div>
                      <div class="empty-state-msg">Try adjusting your search or filters</div>
                    </div>
                  </td></tr>`
                : page.map(d => `
                  <tr data-device-id="${d.id}" class="device-row">
                    <td>
                      <div style="font-weight:600;font-family:'Courier New',monospace;font-size:12px;">${escapeHtml(d.hostname)}</div>
                      ${d.friendly_name && d.friendly_name !== d.hostname
                        ? `<div style="font-size:11px;color:var(--text-muted);">${escapeHtml(d.friendly_name)}</div>`
                        : ''}
                    </td>
                    <td>${statusBadge(d.status)}</td>
                    <td class="mono">${escapeHtml(d.os_build || d.os_version || '—')}</td>
                    <td class="mono">${escapeHtml(d.ip_address || '—')}</td>
                    <td>${routeBadge(d.connection_route)}</td>
                    <td class="mono">${formatRam(d.total_ram_bytes)}</td>
                    <td class="mono" style="font-size:11px;">${formatLastSeen(d.last_seen_at)}</td>
                    <td onclick="event.stopPropagation();">
                      <div style="display:flex;gap:6px;">
                        <button class="btn btn-ghost btn-sm btn-inspect" data-id="${d.id}" title="View Birth Certificate">🔍</button>
                        <button class="btn btn-danger btn-sm btn-delete" data-id="${d.id}" data-hostname="${escapeHtml(d.hostname)}" title="Delete device">🗑️</button>
                      </div>
                    </td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        <div class="pagination">
          <span>Showing ${start + 1}–${Math.min(end, total)} of ${total}</span>
          <div class="pagination-controls">
            <button class="btn btn-ghost btn-sm" id="page-prev" ${_currentPage <= 1 ? 'disabled' : ''}>← Prev</button>
            <button class="btn btn-ghost btn-sm" style="min-width:60px;" disabled>
              ${_currentPage} / ${pages}
            </button>
            <button class="btn btn-ghost btn-sm" id="page-next" ${_currentPage >= pages ? 'disabled' : ''}>Next →</button>
          </div>
        </div>
      </div>
    `;

    attachDeviceTableEvents(container);
  }

  /* ── Attach all event listeners ─────────────────────────────────── */
  function attachDeviceTableEvents(container) {
    // Row click → open birth cert
    container.querySelectorAll('.device-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.getAttribute('data-device-id');
        if (id && window.BirthCertificate) window.BirthCertificate.open(id);
      });
    });

    // Inspect button
    container.querySelectorAll('.btn-inspect').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (window.BirthCertificate) window.BirthCertificate.open(btn.getAttribute('data-id'));
      });
    });

    // Delete button
    container.querySelectorAll('.btn-delete').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id   = btn.getAttribute('data-id');
        const name = btn.getAttribute('data-hostname');
        if (!confirm(`Permanently decommission ${name}?\nThis cannot be undone.`)) return;
        try {
          await window.FleetAPI.deleteDevice(id);
          showToast('success', '🗑️ Device Deleted', `${name} has been decommissioned.`);
          await loadDevices();
        } catch (err) {
          showToast('critical', '❌ Delete Failed', err.message);
        }
      });
    });

    // Search input
    const search = container.querySelector('#device-search');
    if (search) {
      let debounce;
      search.addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(() => {
          _searchTerm = search.value.trim();
          applyFilters();
          renderDeviceTable();
        }, 200);
      });
    }

    // Status filter
    const statusSel = container.querySelector('#device-status-filter');
    if (statusSel) {
      statusSel.addEventListener('change', () => {
        _statusFilter = statusSel.value;
        applyFilters();
        renderDeviceTable();
      });
    }

    // Route filter
    const routeSel = container.querySelector('#device-route-filter');
    if (routeSel) {
      routeSel.addEventListener('change', () => {
        _routeFilter = routeSel.value;
        applyFilters();
        renderDeviceTable();
      });
    }

    // Sort column headers
    container.querySelectorAll('.data-table th[data-sort]').forEach(th => {
      th.addEventListener('click', () => {
        const field = th.getAttribute('data-sort');
        if (_sortField === field) {
          _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          _sortField = field;
          _sortDir   = 'desc';
        }
        applyFilters();
        renderDeviceTable();
      });
    });

    // Pagination
    const prevBtn = container.querySelector('#page-prev');
    const nextBtn = container.querySelector('#page-next');
    if (prevBtn) prevBtn.addEventListener('click', () => { _currentPage--; renderDeviceTable(); });
    if (nextBtn) nextBtn.addEventListener('click', () => { _currentPage++; renderDeviceTable(); });

    // Refresh
    const refBtn = container.querySelector('#devices-refresh-btn');
    if (refBtn) refBtn.addEventListener('click', loadDevices);
  }

  /* ── Load devices from API ──────────────────────────────────────── */
  async function loadDevices() {
    const container = document.getElementById('devices-container');
    if (!container) return;

    // Show skeleton while fetching
    container.innerHTML = `
      <div class="page-header">
        <div>
          <div class="page-title">Device Inventory</div>
          <div class="page-subtitle" style="color:var(--text-muted);">Loading…</div>
        </div>
      </div>
      <div class="glass-card">
        <div style="padding:24px;">
          ${[...Array(5)].map(() => '<div class="skeleton skeleton-text" style="margin-bottom:16px;"></div>').join('')}
        </div>
      </div>
    `;

    try {
      const result = await window.FleetAPI.getDevices({ limit: 500 });
      _allDevices = result.devices || [];
      applyFilters();
      renderDeviceTable();
    } catch (err) {
      container.innerHTML = `
        <div class="glass-card">
          <div class="empty-state">
            <div class="empty-state-icon">❌</div>
            <div class="empty-state-title">Failed to load devices</div>
            <div class="empty-state-msg">${escapeHtml(err.message)}</div>
            <button class="btn btn-ghost" style="margin-top:12px;" onclick="DeviceTable.load()">Retry</button>
          </div>
        </div>
      `;
    }
  }

  /* ── Simple HTML escaper ────────────────────────────────────────── */
  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* ── Toast shortcut ─────────────────────────────────────────────── */
  function showToast(type, title, msg) {
    if (window.App && window.App.toast) window.App.toast(type, title, msg);
  }

  /* ── Expose ─────────────────────────────────────────────────────── */
  window.DeviceTable = {
    load: loadDevices,
    getAll: () => _allDevices
  };
})();
