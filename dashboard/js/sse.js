/**
 * LocalPilot Fleet — SSE Connection Manager
 * dashboard/js/sse.js
 *
 * Connects to /api/v1/events/stream with the fleet key.
 * Dispatches CustomEvents on document:
 *   - fleet:connected
 *   - fleet:disconnected
 *   - fleet:event  (detail: { eventType, data })
 *
 * Auto-reconnects with exponential backoff (1s → 2s → 4s … max 30s).
 */

(function () {
  'use strict';

  let _es         = null;  // EventSource instance
  let _retryTimer = null;
  let _retryDelay = 1000;  // ms
  let _running    = false;
  let _stopped    = false;

  const MAX_DELAY = 30_000;

  /* Helper: dispatch a CustomEvent on document */
  function dispatch(name, detail) {
    document.dispatchEvent(new CustomEvent(name, { detail, bubbles: false }));
  }

  /* Update the SSE status indicator in the sidebar */
  function updateStatusUI(connected) {
    const dot  = document.getElementById('sse-status-dot');
    const text = document.getElementById('sse-status-text');
    if (!dot || !text) return;

    if (connected) {
      dot.className  = 'sse-dot connected';
      text.textContent = 'Live';
    } else {
      dot.className  = 'sse-dot disconnected';
      text.textContent = 'Reconnecting…';
    }
  }

  /* Build the SSE URL, embedding the fleet key as a query param
   * (EventSource doesn't support custom headers in browsers) */
  function buildSseUrl() {
    const base = (localStorage.getItem('fleet_server_url') || '').replace(/\/$/, '') || window.location.origin;
    const key  = localStorage.getItem('fleet_key') || '';
    return `${base}/api/v1/events/stream?key=${encodeURIComponent(key)}`;
  }

  /* Attempt connection */
  function connect() {
    if (_stopped) return;
    if (_es) {
      try { _es.close(); } catch {}
      _es = null;
    }

    const url = buildSseUrl();

    try {
      _es = new EventSource(url);
    } catch (err) {
      console.warn('[SSE] EventSource creation failed:', err.message);
      scheduleReconnect();
      return;
    }

    /* ── onopen ── */
    _es.onopen = () => {
      _retryDelay = 1000;
      _running    = true;
      updateStatusUI(true);
      dispatch('fleet:connected', { timestamp: new Date().toISOString() });
    };

    /* ── Generic message (no event: field) ── */
    _es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        dispatch('fleet:event', { eventType: 'message', data });
      } catch {}
    };

    /* ── Named SSE events ── */
    const namedEvents = [
      'connected',
      'heartbeat',
      'node_enrolled',
      'telemetry_updated',
      'alert_acknowledged',
      'shutdown'
    ];

    for (const eventName of namedEvents) {
      _es.addEventListener(eventName, (ev) => {
        let data = {};
        try { data = JSON.parse(ev.data); } catch {}

        if (eventName === 'connected') {
          // Server confirmed connection
          updateStatusUI(true);
          dispatch('fleet:connected', data);
          return;
        }

        if (eventName === 'shutdown') {
          updateStatusUI(false);
          dispatch('fleet:disconnected', { reason: 'server_shutdown' });
          scheduleReconnect();
          return;
        }

        dispatch('fleet:event', { eventType: eventName, data });
      });
    }

    /* ── onerror ── */
    _es.onerror = () => {
      if (_stopped) return;
      _running = false;
      updateStatusUI(false);
      dispatch('fleet:disconnected', { reason: 'error' });
      try { _es.close(); } catch {}
      _es = null;
      scheduleReconnect();
    };
  }

  /* Schedule a reconnect with exponential backoff */
  function scheduleReconnect() {
    if (_stopped) return;
    if (_retryTimer) return; // already scheduled

    _retryTimer = setTimeout(() => {
      _retryTimer = null;
      connect();
    }, _retryDelay);

    // Exponential backoff, capped at MAX_DELAY
    _retryDelay = Math.min(_retryDelay * 2, MAX_DELAY);
  }

  /**
   * Start the SSE connection. Safe to call multiple times.
   */
  function startSSE() {
    _stopped    = false;
    _retryDelay = 1000;
    if (_es) return; // already running
    connect();
  }

  /**
   * Stop the SSE connection and prevent reconnection.
   */
  function stopSSE() {
    _stopped = true;
    if (_retryTimer) {
      clearTimeout(_retryTimer);
      _retryTimer = null;
    }
    if (_es) {
      try { _es.close(); } catch {}
      _es = null;
    }
    updateStatusUI(false);
    dispatch('fleet:disconnected', { reason: 'manual_stop' });
  }

  /* Expose globally */
  window.SSEManager = { startSSE, stopSSE };
})();
