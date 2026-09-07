/**
 * LocalPilot Fleet — KPI Cards Component
 * dashboard/js/components/kpiCards.js
 *
 * Renders the 6-card KPI strip at the top of the Overview page.
 * Fetches /api/v1/fleet/stats every 30 seconds. Tracks deltas.
 */

(function () {
  'use strict';

  let _refreshInterval = null;
  let _prevStats       = null;

  /* ── KPI card definitions ───────────────────────────────────────── */
  const CARD_DEFS = [
    {
      key:     'total_devices',
      label:   'Total Devices',
      icon:    '🖥️',
      cls:     'kpi-blue',
      format:  v => v,
      deltaKey: null
    },
    {
      key:     'online',
      label:   'Online',
      icon:    '🟢',
      cls:     'kpi-green',
      format:  v => v,
      deltaKey: 'online'
    },
    {
      key:     'offline',
      label:   'Offline',
      icon:    '⚫',
      cls:     'kpi-gray',
      format:  v => v,
      deltaKey: 'offline'
    },
    {
      key:     'drifted',
      label:   'Drifted',
      icon:    '⚠️',
      cls:     'kpi-amber',
      format:  v => v,
      deltaKey: 'drifted'
    },
    {
      key:     'critical_alerts',
      label:   'Critical Alerts',
      icon:    '🔴',
      cls:     'kpi-red',
      format:  v => v,
      deltaKey: 'critical_alerts',
      flash:   true   // flash card if > 0
    },
    {
      key:     'total_fleet_ram_gb',
      label:   'Fleet RAM',
      icon:    '💾',
      cls:     'kpi-purple',
      format:  v => `${v} GB`,
      deltaKey: null
    }
  ];

  /* ── Render skeleton cards while loading ────────────────────────── */
  function renderSkeletons(container) {
    container.innerHTML = `
      <div class="kpi-grid">
        ${CARD_DEFS.map(() => `
          <div class="kpi-card kpi-blue">
            <div class="kpi-header">
              <div class="skeleton skeleton-text" style="width:80px;"></div>
              <div class="skeleton" style="width:28px;height:28px;border-radius:50%;"></div>
            </div>
            <div class="skeleton skeleton-value"></div>
            <div class="skeleton skeleton-text" style="width:50%;margin-top:10px;"></div>
          </div>
        `).join('')}
      </div>
    `;
  }

  /* ── Delta helper ───────────────────────────────────────────────── */
  function getDeltaHtml(curr, prev, key) {
    if (prev === null || key === null) return '<span class="kpi-delta">—</span>';
    const delta = curr[key] - prev[key];
    if (delta === 0) return '<span class="kpi-delta">No change</span>';
    const arrow = delta > 0 ? '↑' : '↓';
    const cls   = delta > 0 ? 'up' : 'down';
    return `<span class="kpi-delta ${cls}">${arrow} ${Math.abs(delta)} since last check</span>`;
  }

  /* ── Render KPI cards from stats ────────────────────────────────── */
  function renderKpiCards(container, stats) {
    const html = `
      <div class="kpi-grid">
        ${CARD_DEFS.map(def => {
          const val   = stats[def.key] ?? 0;
          const flash = def.flash && val > 0 ? ' kpi-critical-flash' : '';
          const delta = getDeltaHtml(stats, _prevStats, def.deltaKey);
          return `
            <div class="kpi-card ${def.cls}${flash}">
              <div class="kpi-header">
                <div class="kpi-label">${def.label}</div>
                <div class="kpi-icon">${def.icon}</div>
              </div>
              <div class="kpi-value">${def.format(val)}</div>
              ${delta}
            </div>
          `;
        }).join('')}
      </div>
    `;

    container.innerHTML = html;
    _prevStats = { ...stats };
  }

  /* ── Main load function ─────────────────────────────────────────── */
  async function loadKpiCards() {
    const container = document.getElementById('kpi-container');
    if (!container) return;

    // Skeleton on first load
    if (!_prevStats) renderSkeletons(container);

    try {
      const stats = await window.FleetAPI.getFleetStats();
      renderKpiCards(container, stats);

      // Also update the nav badge
      const badge = document.getElementById('nav-events-badge');
      if (badge) {
        const count = stats.critical_alerts || 0;
        badge.textContent = count;
        badge.classList.toggle('hidden', count === 0);
      }
    } catch (err) {
      if (!_prevStats) {
        container.innerHTML = `
          <div class="glass-card" style="padding:20px;">
            <div class="empty-state">
              <div class="empty-state-icon">⚠️</div>
              <div class="empty-state-title">Could not load fleet stats</div>
              <div class="empty-state-msg">${err.message}</div>
            </div>
          </div>
        `;
      }
    }
  }

  /* ── Start / stop auto-refresh ──────────────────────────────────── */
  function startKpiRefresh() {
    loadKpiCards();
    if (_refreshInterval) clearInterval(_refreshInterval);
    _refreshInterval = setInterval(loadKpiCards, 30_000);
  }

  function stopKpiRefresh() {
    if (_refreshInterval) {
      clearInterval(_refreshInterval);
      _refreshInterval = null;
    }
  }

  /* ── Expose ─────────────────────────────────────────────────────── */
  window.KpiCards = {
    start: startKpiRefresh,
    stop:  stopKpiRefresh,
    refresh: loadKpiCards
  };
})();
