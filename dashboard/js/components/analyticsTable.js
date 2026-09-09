/**
 * LocalPilot Fleet — Endpoint Analytics & Executive Reports Blade
 * dashboard/js/components/analyticsTable.js
 */

(function () {
  'use strict';

  let currentTab = 'overview'; // 'overview' | 'crashes' | 'reports'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getScoreColor(score) {
    if (score >= 85) return '#10B981'; // green
    if (score >= 70) return '#F59E0B'; // yellow/amber
    return '#EF4444'; // red
  }

  async function loadData() {
    const container = document.getElementById('view-analytics');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">
        <span style="font-size:24px;" class="spin">⏳</span>
        <span>Loading Endpoint Analytics &amp; Fleet Intelligence…</span>
      </div>
    `;

    try {
      const [scores, startup, crashesData, reportsData] = await Promise.all([
        window.FleetAPI.getAnalyticsScores().catch(() => ({})),
        window.FleetAPI.getStartupPerformance().catch(() => ({})),
        window.FleetAPI.getTopCrashes(15).catch(() => ({ top_crashes: [] })),
        window.FleetAPI.getExecutiveReports(15).catch(() => ({ reports: [] }))
      ]);

      renderBlade(container, {
        scores,
        startup,
        crashes: crashesData.top_crashes || [],
        reports: reportsData.reports || []
      });
    } catch (err) {
      container.innerHTML = `
        <div style="padding:24px;color:#EF4444;">
          <h3>Failed to load Endpoint Analytics</h3>
          <p>${esc(err.message)}</p>
        </div>
      `;
    }
  }

  function renderBlade(container, data) {
    const s = data.scores || {};
    const st = data.startup || {};
    const avgScore = s.avg_health_score !== undefined ? s.avg_health_score : 100;
    const scoreColor = getScoreColor(avgScore);

    const html = `
      <div class="blade-header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
        <div>
          <h2 style="margin:0;font-size:20px;font-weight:600;color:var(--text-primary);">📊 Endpoint Analytics &amp; Reports</h2>
          <p style="margin:4px 0 0;font-size:13px;color:var(--text-muted);">
            Proactive user experience scores, startup performance metrics, application reliability telemetry &amp; executive audits.
          </p>
        </div>
        <div style="display:flex;gap:10px;">
          <button class="intune-btn primary" id="btn-generate-report">📄 Generate Report</button>
          <button class="intune-btn" id="btn-refresh-analytics">↻ Refresh</button>
        </div>
      </div>

      <!-- ── KPI Cards Strip ── -->
      <div class="kpi-grid" style="display:grid;grid-template-columns:repeat(4, 1fr);gap:16px;margin-bottom:24px;">
        <div class="kpi-card" style="border-left:4px solid ${scoreColor};background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Fleet Experience Score</div>
          <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
            <div style="font-size:28px;font-weight:700;color:${scoreColor};">${avgScore}</div>
            <div style="font-size:13px;color:var(--text-muted);">/ 100</div>
          </div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
            ${s.scored_devices || 0} of ${s.total_devices || 0} devices scored
          </div>
        </div>

        <div class="kpi-card" style="border-left:4px solid #3B82F6;background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Startup Performance</div>
          <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
            <div style="font-size:28px;font-weight:700;color:var(--text-primary);">${st.avg_boot_seconds || 0}s</div>
            <div style="font-size:12px;color:#10B981;">Score: ${s.avg_startup_score || 100}</div>
          </div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
            Fast boot (<30s): ${st.fast_boot_devices || 0} node(s)
          </div>
        </div>

        <div class="kpi-card" style="border-left:4px solid #10B981;background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">App Reliability</div>
          <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
            <div style="font-size:28px;font-weight:700;color:#10B981;">${s.avg_reliability_score || 100}</div>
            <div style="font-size:13px;color:var(--text-muted);">/ 100</div>
          </div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
            ${data.crashes.length} tracked crashing app(s)
          </div>
        </div>

        <div class="kpi-card" style="border-left:4px solid #8B5CF6;background:#1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">Resource Performance</div>
          <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
            <div style="font-size:28px;font-weight:700;color:#8B5CF6;">${s.avg_resource_score || 100}</div>
            <div style="font-size:13px;color:var(--text-muted);">/ 100</div>
          </div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
            CPU, RAM &amp; Disk Queue Headroom
          </div>
        </div>
      </div>

      <!-- ── Sub-tabs Navigation ── -->
      <div class="sub-tab-bar" style="display:flex;gap:4px;border-bottom:1px solid #334155;margin-bottom:20px;">
        <button class="sub-tab-btn ${currentTab === 'overview' ? 'active' : ''}" data-subtab="overview">
          📈 Endpoint Analytics
        </button>
        <button class="sub-tab-btn ${currentTab === 'crashes' ? 'active' : ''}" data-subtab="crashes">
          💥 Application Reliability (${data.crashes.length})
        </button>
        <button class="sub-tab-btn ${currentTab === 'reports' ? 'active' : ''}" data-subtab="reports">
          📋 Executive Reports (${data.reports.length})
        </button>
      </div>

      <!-- ── Tab Content Container ── -->
      <div id="analytics-subtab-content"></div>
    `;

    container.innerHTML = html;

    // Attach subtab click events
    container.querySelectorAll('.sub-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        currentTab = btn.getAttribute('data-subtab');
        renderBlade(container, data);
      });
    });

    // Render active subtab
    const content = container.querySelector('#analytics-subtab-content');
    if (currentTab === 'overview') {
      renderOverviewTab(content, data);
    } else if (currentTab === 'crashes') {
      renderCrashesTab(content, data.crashes);
    } else if (currentTab === 'reports') {
      renderReportsTab(content, data.reports);
    }

    // Attach actions
    container.querySelector('#btn-refresh-analytics')?.addEventListener('click', loadData);
    container.querySelector('#btn-generate-report')?.addEventListener('click', showGenerateReportModal);
  }

  function renderOverviewTab(el, data) {
    const s = data.scores || {};
    const dist = s.distribution || { excellent: 0, good: 0, needs_attention: 0 };
    const st = data.startup || {};

    el.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px;">
        <!-- Score Distribution Card -->
        <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;">
          <h3 style="margin:0 0 16px;font-size:15px;color:var(--text-primary);">🎯 Fleet Score Distribution</h3>
          <div style="display:flex;flex-direction:column;gap:12px;">
            <div>
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
                <span style="color:#10B981;font-weight:600;">Excellent (85-100)</span>
                <span>${dist.excellent} node(s)</span>
              </div>
              <div style="background:#334155;border-radius:4px;height:8px;overflow:hidden;">
                <div style="background:#10B981;height:100%;width:${(s.scored_devices ? (dist.excellent / s.scored_devices) * 100 : 0)}%;"></div>
              </div>
            </div>
            <div>
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
                <span style="color:#F59E0B;font-weight:600;">Good (70-84)</span>
                <span>${dist.good} node(s)</span>
              </div>
              <div style="background:#334155;border-radius:4px;height:8px;overflow:hidden;">
                <div style="background:#F59E0B;height:100%;width:${(s.scored_devices ? (dist.good / s.scored_devices) * 100 : 0)}%;"></div>
              </div>
            </div>
            <div>
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
                <span style="color:#EF4444;font-weight:600;">Needs Attention (&lt;70)</span>
                <span>${dist.needs_attention} node(s)</span>
              </div>
              <div style="background:#334155;border-radius:4px;height:8px;overflow:hidden;">
                <div style="background:#EF4444;height:100%;width:${(s.scored_devices ? (dist.needs_attention / s.scored_devices) * 100 : 0)}%;"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Startup Performance Breakdown -->
        <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;">
          <h3 style="margin:0 0 16px;font-size:15px;color:var(--text-primary);">⚡ Startup &amp; Sign-In Duration</h3>
          <div style="display:flex;flex-direction:column;gap:14px;font-size:13px;">
            <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid #334155;">
              <span style="color:var(--text-muted);">Average Core Boot Duration:</span>
              <span style="font-weight:600;color:var(--text-primary);">${st.avg_boot_seconds || 0} sec</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid #334155;">
              <span style="color:var(--text-muted);">Average Responsive Sign-In:</span>
              <span style="font-weight:600;color:var(--text-primary);">${st.avg_signin_seconds || 0} sec</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding-bottom:8px;border-bottom:1px solid #334155;">
              <span style="color:var(--text-muted);">Moderate Boot Time (30-60s):</span>
              <span style="color:#F59E0B;font-weight:600;">${st.moderate_boot_devices || 0} node(s)</span>
            </div>
            <div style="display:flex;justify-content:space-between;">
              <span style="color:var(--text-muted);">Slow Boot Bottlenecks (&gt;60s):</span>
              <span style="color:#EF4444;font-weight:600;">${st.slow_boot_devices || 0} node(s)</span>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  function renderCrashesTab(el, crashes) {
    if (!crashes || crashes.length === 0) {
      el.innerHTML = `
        <div style="padding:36px;text-align:center;background:#1e293b;border-radius:8px;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">✨</div>
          <div style="font-size:15px;font-weight:600;color:var(--text-primary);">Clean Reliability Record</div>
          <div style="font-size:13px;margin-top:4px;">No application crashes or hangs reported in the fleet over the last 24 hours.</div>
        </div>
      `;
      return;
    }

    let rowsHtml = '';
    crashes.forEach(c => {
      rowsHtml += `
        <tr>
          <td style="font-weight:600;color:var(--text-primary);">${esc(c.app_name)}</td>
          <td><span class="badge" style="background:rgba(239,68,68,0.15);color:#EF4444;font-weight:700;">${c.crash_count}</span></td>
          <td><span class="badge" style="background:rgba(245,158,11,0.15);color:#F59E0B;">${c.hang_count}</span></td>
          <td>${c.affected_devices} device(s)</td>
          <td style="font-size:12px;color:var(--text-muted);">${c.last_occurred_at ? new Date(c.last_occurred_at).toLocaleString() : 'Recent'}</td>
        </tr>
      `;
    });

    el.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="border-bottom:1px solid #334155;text-align:left;font-size:12px;color:var(--text-muted);">
              <th style="padding:12px 16px;">Application Binary</th>
              <th style="padding:12px 16px;">Crashes (24h)</th>
              <th style="padding:12px 16px;">Hangs (24h)</th>
              <th style="padding:12px 16px;">Impacted Fleet Nodes</th>
              <th style="padding:12px 16px;">Last Failure Event</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;
  }

  function renderReportsTab(el, reports) {
    if (!reports || reports.length === 0) {
      el.innerHTML = `
        <div style="padding:36px;text-align:center;background:#1e293b;border-radius:8px;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">📄</div>
          <div style="font-size:15px;font-weight:600;color:var(--text-primary);">No Executive Reports Generated Yet</div>
          <div style="font-size:13px;margin-top:4px;">Click "Generate Report" above to compile a full compliance, security, or health audit.</div>
        </div>
      `;
      return;
    }

    let rowsHtml = '';
    reports.forEach(r => {
      const typeColor = r.report_type === 'SECURITY_POSTURE' ? '#EF4444' : (r.report_type === 'COMPLIANCE_AUDIT' ? '#3B82F6' : '#10B981');
      rowsHtml += `
        <tr>
          <td><span class="status-pill" style="color:${typeColor};border-color:${typeColor};font-size:11px;">${esc(r.report_type)}</span></td>
          <td style="font-size:12px;color:var(--text-muted);">${new Date(r.generated_at).toLocaleString()}</td>
          <td style="font-size:12px;">${esc(r.created_by)}</td>
          <td>
            <button class="intune-btn small btn-view-report-summary" data-report-id="${esc(r.id)}">👁️ View Summary</button>
          </td>
        </tr>
      `;
    });

    el.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="border-bottom:1px solid #334155;text-align:left;font-size:12px;color:var(--text-muted);">
              <th style="padding:12px 16px;">Report Type</th>
              <th style="padding:12px 16px;">Generated Timestamp</th>
              <th style="padding:12px 16px;">Author / Initiator</th>
              <th style="padding:12px 16px;">Actions</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;

    el.querySelectorAll('.btn-view-report-summary').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-report-id');
        try {
          const report = await window.FleetAPI.getExecutiveReport(id);
          showReportSummaryModal(report);
        } catch (err) {
          alert(`Failed to fetch report: ${err.message}`);
        }
      });
    });
  }

  function showGenerateReportModal() {
    let modal = document.getElementById('generate-report-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'generate-report-modal';
      modal.className = 'modal-backdrop';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="modal-card" style="max-width:500px;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:17px;color:var(--text-primary);">📄 Compile Executive Intune Report</h3>
          <button class="close-btn" id="btn-close-report-modal" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;">✕</button>
        </div>
        <p style="font-size:13px;color:var(--text-muted);margin:0 0 16px;">
          Select an executive audit framework to synthesize live fleet telemetry into an immutable compliance artifact.
        </p>
        <div style="margin-bottom:16px;">
          <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:6px;">REPORT AUDIT TYPE</label>
          <select id="modal-report-type" class="intune-input" style="width:100%;padding:8px;background:#1e293b;border:1px solid #334155;color:var(--text-primary);border-radius:6px;">
            <option value="FLEET_HEALTH">📊 Fleet Health &amp; Endpoint Analytics Experience</option>
            <option value="COMPLIANCE_AUDIT">🛡️ Zero-Trust Device Compliance &amp; BitLocker Audit</option>
            <option value="SECURITY_POSTURE">🔒 Microsoft Defender Antivirus &amp; ASR Perimeter Audit</option>
          </select>
        </div>
        <div style="display:flex;justify-content:flex-end;gap:10px;">
          <button class="intune-btn" id="btn-cancel-gen-report">Cancel</button>
          <button class="intune-btn primary" id="btn-submit-gen-report">Generate Now</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';

    modal.querySelector('#btn-close-report-modal')?.addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#btn-cancel-gen-report')?.addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#btn-submit-gen-report')?.addEventListener('click', async () => {
      const reportType = modal.querySelector('#modal-report-type').value;
      const submitBtn = modal.querySelector('#btn-submit-gen-report');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Compiling…';

      try {
        await window.FleetAPI.generateExecutiveReport(reportType);
        modal.style.display = 'none';
        if (typeof showToast === 'function') showToast('Report Generated', `Executive report ${reportType} compiled successfully.`, 'info');
        loadData();
      } catch (err) {
        alert(`Failed to compile report: ${err.message}`);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Generate Now';
      }
    });
  }

  function showReportSummaryModal(report) {
    let modal = document.getElementById('report-summary-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'report-summary-modal';
      modal.className = 'modal-backdrop';
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="modal-card" style="max-width:650px;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px;max-height:85vh;overflow-y:auto;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div>
            <h3 style="margin:0;font-size:17px;color:var(--text-primary);">${esc(report.report_type)}</h3>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Generated ${new Date(report.generated_at).toLocaleString()} by ${esc(report.created_by)}</div>
          </div>
          <button class="close-btn" id="btn-close-summary-modal" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;">✕</button>
        </div>
        <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;padding:16px;font-family:monospace;font-size:12px;color:#38BDF8;overflow-x:auto;white-space:pre-wrap;">${esc(JSON.stringify(report.summary, null, 2))}</div>
        <div style="display:flex;justify-content:flex-end;margin-top:16px;">
          <button class="intune-btn" id="btn-dismiss-summary-modal">Close</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';
    modal.querySelector('#btn-close-summary-modal')?.addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#btn-dismiss-summary-modal')?.addEventListener('click', () => modal.style.display = 'none');
  }

  window.AnalyticsTable = {
    init: loadData,
    refresh: loadData
  };
})();
