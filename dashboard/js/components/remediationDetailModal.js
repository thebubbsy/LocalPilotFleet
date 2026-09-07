/**
 * LocalPilot Fleet — Proactive Remediation Detail & Execution Log Modal
 * dashboard/js/components/remediationDetailModal.js
 */

(function () {
  let _currentPkg = null;

  function esc(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  async function open(packageId) {
    try {
      _currentPkg = await window.FleetAPI.getRemediationDetails(packageId);
      renderModal();
    } catch (err) {
      if (typeof showToast === 'function') {
        showToast('Error', 'Failed to load remediation package: ' + err.message, 'critical');
      }
    }
  }

  function close() {
    const modal = document.getElementById('rem-detail-modal');
    if (modal) modal.remove();
  }

  function renderModal() {
    close();

    const p = _currentPkg;
    if (!p) return;

    const modal = document.createElement('div');
    modal.id = 'rem-detail-modal';
    modal.className = 'modal-overlay';
    modal.style.display = 'flex';

    modal.innerHTML = `
      <div class="modal-dialog" style="max-width: 900px; width: 95%; max-height: 90vh; display: flex; flex-direction: column;">
        <div class="modal-header" style="display: flex; justify-content: space-between; align-items: flex-start; padding: 16px 20px; border-bottom: 1px solid var(--border-color);">
          <div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 20px;">🩺</span>
              <h3 style="margin: 0; font-size: 18px; color: var(--text-primary);">${esc(p.name)}</h3>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
              ID: <code>${esc(p.id)}</code> • Publisher: <strong>${esc(p.publisher)}</strong> • Target: <strong>${esc(p.target_group_name || 'All Devices')}</strong>
            </div>
          </div>
          <div style="display: flex; gap: 8px; align-items: center;">
            <button class="btn btn-primary btn-sm" id="btn-modal-run-now">⚡ Run on Fleet Now</button>
            <button class="btn-close" id="btn-modal-close" style="background: none; border: none; font-size: 20px; cursor: pointer; color: var(--text-muted);">&times;</button>
          </div>
        </div>

        <div class="modal-body" style="padding: 20px; overflow-y: auto; flex: 1;">
          <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 18px; line-height: 1.5; background: var(--bg-hover); padding: 12px; border-radius: 6px;">
            ${esc(p.description || 'No description provided.')}
          </div>

          <!-- Tabs for Code View -->
          <div style="display: flex; gap: 10px; border-bottom: 1px solid var(--border-color); margin-bottom: 14px;">
            <button class="tab-btn active" id="tab-det-code" style="padding: 8px 16px; background: none; border: none; border-bottom: 2px solid var(--accent-blue); color: var(--accent-blue); font-weight: 600; cursor: pointer;">
              🔍 Detection Script
            </button>
            <button class="tab-btn" id="tab-rem-code" style="padding: 8px 16px; background: none; border: none; color: var(--text-muted); font-weight: 600; cursor: pointer;">
              🩺 Remediation Script
            </button>
            <button class="tab-btn" id="tab-history" style="padding: 8px 16px; background: none; border: none; color: var(--text-muted); font-weight: 600; cursor: pointer;">
              📊 Device Run History (${(p.runs || []).length})
            </button>
          </div>

          <!-- Tab Content: Detection -->
          <div id="content-det-code" class="tab-content" style="display: block;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <span style="font-size: 12px; color: var(--text-muted);">PowerShell (exit 0 = healthy, exit 1 = issue detected)</span>
              <button class="btn-action-sm" id="btn-copy-det">📋 Copy</button>
            </div>
            <pre style="background: #0D1117; color: #E6EDF3; padding: 14px; border-radius: 6px; font-size: 12px; font-family: monospace; overflow-x: auto; max-height: 260px; border: 1px solid var(--border-color);"><code>${esc(p.detection_script)}</code></pre>
          </div>

          <!-- Tab Content: Remediation -->
          <div id="content-rem-code" class="tab-content" style="display: none;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <span style="font-size: 12px; color: var(--text-muted);">PowerShell (runs when detection exits 1, exit 0 = resolved)</span>
              <button class="btn-action-sm" id="btn-copy-rem">📋 Copy</button>
            </div>
            <pre style="background: #0D1117; color: #E6EDF3; padding: 14px; border-radius: 6px; font-size: 12px; font-family: monospace; overflow-x: auto; max-height: 260px; border: 1px solid var(--border-color);"><code>${esc(p.remediation_script)}</code></pre>
          </div>

          <!-- Tab Content: Run History -->
          <div id="content-history" class="tab-content" style="display: none;">
            ${renderRunHistory(p.runs || [])}
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    bindModalEvents(modal, p);
  }

  function renderRunHistory(runs) {
    if (runs.length === 0) {
      return `
        <div style="text-align: center; padding: 32px; color: var(--text-muted);">
          No execution runs recorded for this script package yet.
        </div>
      `;
    }

    return `
      <table class="data-table" style="font-size: 12px;">
        <thead>
          <tr>
            <th>Device</th>
            <th>Primary User</th>
            <th>Detection Status</th>
            <th>Remediation Status</th>
            <th>Executed At</th>
            <th style="text-align: right;">Output</th>
          </tr>
        </thead>
        <tbody>
          ${runs.map((r, idx) => {
            const isNoIssue = r.detection_status === 'NO_ISSUE';
            const detBadge = isNoIssue
              ? '<span class="badge badge-online">No issue (0)</span>'
              : '<span class="badge" style="background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b55;">Issue Found (1)</span>';

            let remBadge = '<span class="badge badge-offline">Not Needed</span>';
            if (r.remediation_status === 'REMEDIATED') {
              remBadge = '<span class="badge" style="background:#10b98122;color:#10b981;border:1px solid #10b98155;">Remediated (0)</span>';
            } else if (r.remediation_status === 'FAILED') {
              remBadge = '<span class="badge badge-quarantined">Failed (1)</span>';
            }

            return `
              <tr>
                <td style="font-weight: 600;">💻 ${esc(r.friendly_name || r.hostname)}</td>
                <td style="color: var(--text-secondary);">${esc(r.primary_user || '—')}</td>
                <td>${detBadge}</td>
                <td>${remBadge}</td>
                <td style="color: var(--text-muted);">${new Date(r.executed_at).toLocaleString()}</td>
                <td style="text-align: right;">
                  <button class="btn-action-sm btn-toggle-run-out" data-idx="${idx}">Inspect ▾</button>
                </td>
              </tr>
              <tr id="run-out-${idx}" style="display: none; background: var(--bg-hover);">
                <td colspan="6" style="padding: 12px;">
                  <div style="margin-bottom: 6px; font-weight: 600; color: var(--text-secondary);">Detection Output:</div>
                  <pre style="background: #000; color: #ccc; padding: 8px; border-radius: 4px; max-height: 120px; overflow-y: auto;">${esc(r.detection_stdout || r.detection_stderr || '(No output)')}</pre>
                  ${r.remediation_stdout || r.remediation_stderr ? `
                    <div style="margin: 8px 0 4px; font-weight: 600; color: var(--text-secondary);">Remediation Output:</div>
                    <pre style="background: #000; color: #10B981; padding: 8px; border-radius: 4px; max-height: 120px; overflow-y: auto;">${esc(r.remediation_stdout || r.remediation_stderr)}</pre>
                  ` : ''}
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function bindModalEvents(modal, p) {
    modal.querySelector('#btn-modal-close')?.addEventListener('click', close);
    modal.addEventListener('click', (e) => {
      if (e.target === modal) close();
    });

    const tabDet = modal.querySelector('#tab-det-code');
    const tabRem = modal.querySelector('#tab-rem-code');
    const tabHist = modal.querySelector('#tab-history');

    const cDet = modal.querySelector('#content-det-code');
    const cRem = modal.querySelector('#content-rem-code');
    const cHist = modal.querySelector('#content-history');

    function selectTab(btn, content) {
      [tabDet, tabRem, tabHist].forEach(b => {
        b.style.borderBottom = 'none';
        b.style.color = 'var(--text-muted)';
      });
      [cDet, cRem, cHist].forEach(c => c.style.display = 'none');

      btn.style.borderBottom = '2px solid var(--accent-blue)';
      btn.style.color = 'var(--accent-blue)';
      content.style.display = 'block';
    }

    tabDet?.addEventListener('click', () => selectTab(tabDet, cDet));
    tabRem?.addEventListener('click', () => selectTab(tabRem, cRem));
    tabHist?.addEventListener('click', () => selectTab(tabHist, cHist));

    modal.querySelector('#btn-copy-det')?.addEventListener('click', () => {
      navigator.clipboard.writeText(p.detection_script);
      if (typeof showToast === 'function') showToast('Copied', 'Detection script copied to clipboard', 'info');
    });

    modal.querySelector('#btn-copy-rem')?.addEventListener('click', () => {
      navigator.clipboard.writeText(p.remediation_script);
      if (typeof showToast === 'function') showToast('Copied', 'Remediation script copied to clipboard', 'info');
    });

    modal.querySelector('#btn-modal-run-now')?.addEventListener('click', async (e) => {
      const btn = e.target;
      btn.disabled = true;
      btn.textContent = '⏳ Queuing…';
      try {
        const res = await window.FleetAPI.runRemediationNow(p.id);
        if (typeof showToast === 'function') {
          showToast('Dispatched', `Queued "${res.remediation_name}" on ${res.target_count} device(s)`, 'success');
        }
        btn.textContent = '✓ Queued';
        setTimeout(() => {
          btn.disabled = false;
          btn.textContent = '⚡ Run on Fleet Now';
        }, 2000);
      } catch (err) {
        if (typeof showToast === 'function') showToast('Error', err.message, 'critical');
        btn.disabled = false;
        btn.textContent = '⚡ Run on Fleet Now';
      }
    });

    modal.querySelectorAll('.btn-toggle-run-out').forEach(b => {
      b.addEventListener('click', () => {
        const idx = b.getAttribute('data-idx');
        const row = modal.querySelector(`#run-out-${idx}`);
        if (row) {
          const isHidden = row.style.display === 'none';
          row.style.display = isHidden ? 'table-row' : 'none';
          b.textContent = isHidden ? 'Hide ▴' : 'Inspect ▾';
        }
      });
    });
  }

  window.RemediationDetailModal = {
    open,
    close
  };
})();
