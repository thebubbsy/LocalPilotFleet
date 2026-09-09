/**
 * LocalPilot Fleet — Microsoft Defender Vulnerability Management & Security Baselines Blade
 * dashboard/js/components/vulnerabilitiesTable.js
 */

(function () {
  'use strict';

  let currentSubTab = 'cves'; // 'cves' | 'exposures' | 'baselines'
  let cachedStats = null;
  let cachedVulns = [];
  let cachedBaselines = [];
  let searchQuery = '';
  let selectedSeverity = '';

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getSeverityBadge(sev) {
    const s = String(sev || 'LOW').toUpperCase();
    if (s === 'CRITICAL') {
      return '<span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-weight:700;border:1px solid #ef444455;">🔴 CRITICAL</span>';
    } else if (s === 'HIGH') {
      return '<span class="badge" style="background:rgba(245,158,11,0.2);color:#f59e0b;font-weight:700;border:1px solid #f59e0b55;">🟠 HIGH</span>';
    } else if (s === 'MEDIUM') {
      return '<span class="badge" style="background:rgba(59,130,246,0.15);color:#3b82f6;font-weight:600;">🟡 MEDIUM</span>';
    }
    return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#9ca3af;">🟢 LOW</span>';
  }

  function getExploitBadge(status) {
    const s = String(status || 'NONE').toUpperCase();
    if (s === 'WEAPONIZED_WILD') {
      return '<span class="badge" style="background:rgba(220,38,38,0.25);color:#dc2626;font-weight:700;animation:pulse 2s infinite;">⚡ WEAPONIZED (WILD)</span>';
    } else if (s === 'ACTIVE_EXPLOIT_POC') {
      return '<span class="badge" style="background:rgba(245,158,11,0.2);color:#f59e0b;font-weight:600;">⚠️ POC AVAILABLE</span>';
    }
    return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#64748b;font-size:11px;">NO KNOWN EXPLOIT</span>';
  }

  async function loadData() {
    try {
      const [stats, vulnsData, baselinesData] = await Promise.all([
        window.FleetAPI.getTvmStats().catch(() => ({})),
        window.FleetAPI.getTvmVulnerabilities().catch(() => ({ vulnerabilities: [] })),
        window.FleetAPI.getTvmBaselines().catch(() => ({ baselines: [] }))
      ]);

      cachedStats = stats;
      cachedVulns = vulnsData.vulnerabilities || [];
      cachedBaselines = baselinesData.baselines || [];
    } catch (e) {
      console.error('Failed to load TVM data:', e);
    }
  }

  async function render(container) {
    if (!container) {
      container = document.getElementById('view-vulnerabilities') || document.getElementById('tab-vulnerabilities');
    }
    if (!container) return;

    container.innerHTML = '<div style="padding:2rem;text-align:center;color:#94a3b8;"><div class="spinner"></div> Loading Defender Vulnerability Management & Security Baselines...</div>';

    await loadData();

    const stats = cachedStats || {};
    const totalCves = stats.total_cves || cachedVulns.length || 0;
    const critAndHigh = (stats.critical_cves || 0) + (stats.high_cves || 0);
    const affectedDevices = stats.affected_devices || 0;
    const activeExploits = stats.active_exploits_count || 0;

    let html = `
      <div class="blade-header" style="margin-bottom:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;">
          <div>
            <h1 style="font-size:1.5rem;font-weight:700;color:#f8fafc;margin:0 0 0.25rem 0;display:flex;align-items:center;gap:0.5rem;">
              <span>🛡️</span> Vulnerability Management (TVM) & Security Baselines
            </h1>
            <p style="color:#94a3b8;margin:0;font-size:0.875rem;">
              Microsoft Defender Vulnerability Management (TVM), CVSS v3 severity posture, workstation software CVE exposure assessment, and Intune hardened security baselines.
            </p>
          </div>
          <div style="display:flex;gap:0.75rem;">
            <button class="btn btn-secondary" id="btn-refresh-tvm" style="display:flex;align-items:center;gap:0.4rem;">
              <span>🔄</span> Refresh
            </button>
            <button class="btn btn-primary" id="btn-add-cve" style="display:flex;align-items:center;gap:0.4rem;background:#ef4444;">
              <span>➕</span> Add Vulnerability (CVE)
            </button>
          </div>
        </div>
      </div>

      <!-- KPI Summary Cards -->
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin-bottom:1.5rem;">
        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Total Tracked CVEs</div>
          <div style="font-size:1.8rem;font-weight:700;color:#38bdf8;">${totalCves}</div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">Known software vulnerabilities</div>
        </div>

        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Critical & High CVEs</div>
          <div style="font-size:1.8rem;font-weight:700;color:${critAndHigh > 0 ? '#ef4444' : '#10b981'};">${critAndHigh}</div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">CVSS 7.0 - 10.0 range</div>
        </div>

        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Exposed Workstations</div>
          <div style="font-size:1.8rem;font-weight:700;color:${affectedDevices > 0 ? '#f59e0b' : '#10b981'};">${affectedDevices}</div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">Nodes running vulnerable software</div>
        </div>

        <div class="card kpi-card" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;">
          <div style="color:#94a3b8;font-size:0.75rem;text-transform:uppercase;font-weight:600;letter-spacing:0.05em;margin-bottom:0.4rem;">Active In-The-Wild Exploits</div>
          <div style="font-size:1.8rem;font-weight:700;color:${activeExploits > 0 ? '#dc2626' : '#10b981'};">${activeExploits}</div>
          <div style="font-size:0.8rem;color:#64748b;margin-top:0.25rem;">Weaponized PoC / In-the-wild</div>
        </div>
      </div>

      <!-- Navigation Subtabs -->
      <div style="display:flex;gap:0.5rem;border-bottom:1px solid #334155;margin-bottom:1.5rem;padding-bottom:0.5rem;">
        <button class="btn btn-subtab ${currentSubTab === 'cves' ? 'active' : ''}" data-subtab="cves" style="background:${currentSubTab === 'cves' ? '#334155' : 'transparent'};color:${currentSubTab === 'cves' ? '#38bdf8' : '#94a3b8'};border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:0.4rem;">
          <span>🛡️</span> Vulnerabilities & CVEs (${cachedVulns.length})
        </button>
        <button class="btn btn-subtab ${currentSubTab === 'exposures' ? 'active' : ''}" data-subtab="exposures" style="background:${currentSubTab === 'exposures' ? '#334155' : 'transparent'};color:${currentSubTab === 'exposures' ? '#38bdf8' : '#94a3b8'};border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:0.4rem;">
          <span>💻</span> Exposed Workstations (${stats.active_device_exposures || 0})
        </button>
        <button class="btn btn-subtab ${currentSubTab === 'baselines' ? 'active' : ''}" data-subtab="baselines" style="background:${currentSubTab === 'baselines' ? '#334155' : 'transparent'};color:${currentSubTab === 'baselines' ? '#38bdf8' : '#94a3b8'};border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:0.4rem;">
          <span>📋</span> Security Baselines (${cachedBaselines.length})
        </button>
      </div>

      <!-- Subtab Container -->
      <div id="tvm-subtab-content">
    `;

    if (currentSubTab === 'cves') {
      html += renderCvesSubtab();
    } else if (currentSubTab === 'exposures') {
      html += renderExposuresSubtab();
    } else {
      html += renderBaselinesSubtab();
    }

    html += '</div>';

    container.innerHTML = html;
    attachEvents(container);
  }

  function renderCvesSubtab() {
    let filtered = cachedVulns.slice();
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(v =>
        (v.cve_id && v.cve_id.toLowerCase().includes(q)) ||
        (v.title && v.title.toLowerCase().includes(q)) ||
        (v.software_name && v.software_name.toLowerCase().includes(q))
      );
    }
    if (selectedSeverity) {
      filtered = filtered.filter(v => v.severity === selectedSeverity);
    }

    let out = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;gap:1rem;flex-wrap:wrap;">
        <div style="display:flex;gap:0.75rem;flex:1;max-width:600px;">
          <input type="text" id="tvm-search-input" class="form-control" placeholder="Search CVEs by identifier, title, software..." value="${esc(searchQuery)}" style="background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem 0.75rem;border-radius:6px;flex:1;">
          <select id="tvm-sev-select" class="form-control" style="background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem 0.75rem;border-radius:6px;width:160px;">
            <option value="">All Severities</option>
            <option value="CRITICAL" ${selectedSeverity === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
            <option value="HIGH" ${selectedSeverity === 'HIGH' ? 'selected' : ''}>HIGH</option>
            <option value="MEDIUM" ${selectedSeverity === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
            <option value="LOW" ${selectedSeverity === 'LOW' ? 'selected' : ''}>LOW</option>
          </select>
        </div>
        <div style="color:#94a3b8;font-size:0.85rem;">Showing ${filtered.length} of ${cachedVulns.length} vulnerabilities</div>
      </div>

      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.875rem;">
          <thead>
            <tr style="border-bottom:1px solid #334155;background:#0f172a;color:#94a3b8;">
              <th style="padding:0.75rem 1rem;">Vulnerability (CVE)</th>
              <th style="padding:0.75rem 1rem;">Affected Software</th>
              <th style="padding:0.75rem 1rem;">CVSS v3</th>
              <th style="padding:0.75rem 1rem;">Severity</th>
              <th style="padding:0.75rem 1rem;">Exploit Posture</th>
              <th style="padding:0.75rem 1rem;">Exposed Devices</th>
              <th style="padding:0.75rem 1rem;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    if (filtered.length === 0) {
      out += `
        <tr>
          <td colspan="7" style="padding:3rem;text-align:center;color:#64748b;">
            No vulnerabilities found matching filters.
          </td>
        </tr>
      `;
    } else {
      filtered.forEach(v => {
        out += `
          <tr style="border-bottom:1px solid #334155;transition:background 0.15s;" onmouseover="this.style.background='rgba(51,65,85,0.4)'" onmouseout="this.style.background='transparent'">
            <td style="padding:0.75rem 1rem;font-weight:600;color:#f8fafc;">
              <div style="display:flex;align-items:center;gap:0.5rem;">
                <span style="font-family:monospace;color:#38bdf8;font-weight:700;">${esc(v.cve_id)}</span>
              </div>
              <div style="font-size:0.8rem;color:#94a3b8;margin-top:2px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                ${esc(v.title)}
              </div>
            </td>
            <td style="padding:0.75rem 1rem;color:#cbd5e1;">
              <div>${esc(v.software_name)}</div>
              <div style="font-size:0.75rem;color:#64748b;font-family:monospace;">Ver: ${esc(v.affected_versions)}</div>
            </td>
            <td style="padding:0.75rem 1rem;font-family:monospace;font-weight:700;color:${v.cvss_score >= 9 ? '#ef4444' : (v.cvss_score >= 7 ? '#f59e0b' : '#38bdf8')};">
              ${v.cvss_score ? v.cvss_score.toFixed(1) : '0.0'}
            </td>
            <td style="padding:0.75rem 1rem;">${getSeverityBadge(v.severity)}</td>
            <td style="padding:0.75rem 1rem;">${getExploitBadge(v.exploit_status)}</td>
            <td style="padding:0.75rem 1rem;">
              ${v.exposed_devices_count > 0 ? `<span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-weight:700;">⚠️ ${v.exposed_devices_count} exposed</span>` : '<span style="color:#10b981;font-size:11px;">✔ Clean</span>'}
            </td>
            <td style="padding:0.75rem 1rem;text-align:right;">
              <div style="display:flex;gap:0.4rem;justify-content:flex-end;">
                <button class="btn btn-xs btn-view-vuln" data-cve-id="${esc(v.cve_id)}" style="background:#334155;color:#38bdf8;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;">
                  🔍 Inspect
                </button>
                <button class="btn btn-xs btn-delete-vuln" data-cve-id="${esc(v.cve_id)}" style="background:rgba(239,68,68,0.15);color:#ef4444;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;">
                  🗑️
                </button>
              </div>
            </td>
          </tr>
        `;
      });
    }

    out += '</tbody></table></div>';
    return out;
  }

  function renderExposuresSubtab() {
    let out = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.875rem;">
          <thead>
            <tr style="border-bottom:1px solid #334155;background:#0f172a;color:#94a3b8;">
              <th style="padding:0.75rem 1rem;">Vulnerability (CVE)</th>
              <th style="padding:0.75rem 1rem;">Detected Software</th>
              <th style="padding:0.75rem 1rem;">Installed Version</th>
              <th style="padding:0.75rem 1rem;">CVSS Score</th>
              <th style="padding:0.75rem 1rem;">Severity</th>
              <th style="padding:0.75rem 1rem;">Status</th>
              <th style="padding:0.75rem 1rem;text-align:right;">Remediation</th>
            </tr>
          </thead>
          <tbody>
    `;

    const vulnsWithExposures = cachedVulns.filter(v => v.exposed_devices_count > 0);

    if (vulnsWithExposures.length === 0) {
      out += `
        <tr>
          <td colspan="7" style="padding:3rem;text-align:center;color:#64748b;">
            No active workstation CVE exposures detected. All nodes are compliant with known security baselines.
          </td>
        </tr>
      `;
    } else {
      vulnsWithExposures.forEach(v => {
        out += `
          <tr style="border-bottom:1px solid #334155;">
            <td style="padding:0.75rem 1rem;font-weight:600;color:#f8fafc;">
              <span style="font-family:monospace;color:#38bdf8;">${esc(v.cve_id)}</span>
              <div style="font-size:0.75rem;color:#94a3b8;">${esc(v.title)}</div>
            </td>
            <td style="padding:0.75rem 1rem;color:#cbd5e1;">${esc(v.software_name)}</td>
            <td style="padding:0.75rem 1rem;font-family:monospace;color:#94a3b8;">${esc(v.affected_versions)}</td>
            <td style="padding:0.75rem 1rem;font-family:monospace;font-weight:700;color:#ef4444;">${v.cvss_score.toFixed(1)}</td>
            <td style="padding:0.75rem 1rem;">${getSeverityBadge(v.severity)}</td>
            <td style="padding:0.75rem 1rem;">
              <span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-weight:700;">ACTIVE EXPOSURE</span>
            </td>
            <td style="padding:0.75rem 1rem;text-align:right;color:#38bdf8;font-size:0.8rem;">
              ${esc(v.remediation_guidance || 'Upgrade to latest vendor release')}
            </td>
          </tr>
        `;
      });
    }

    out += '</tbody></table></div>';
    return out;
  }

  function renderBaselinesSubtab() {
    let out = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
        <div style="color:#94a3b8;font-size:0.85rem;">Hardened Intune & Defender security baseline profiles (${cachedBaselines.length})</div>
        <button class="btn btn-sm btn-primary" id="btn-create-baseline" style="background:#3b82f6;color:#fff;border:none;padding:0.4rem 0.8rem;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;">
          ➕ Create Baseline
        </button>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:1rem;">
    `;

    if (cachedBaselines.length === 0) {
      out += '<div style="color:#64748b;grid-column:1/-1;text-align:center;padding:3rem;">No security baseline profiles configured.</div>';
    } else {
      cachedBaselines.forEach(b => {
        const rules = b.parsed_rules || [];
        out += `
          <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1.2rem;display:flex;flex-direction:column;justify-content:space-between;">
            <div>
              <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.5rem;">
                <h4 style="margin:0;color:#f8fafc;font-size:1rem;">${esc(b.name)}</h4>
                <span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;font-size:11px;">${esc(b.category)}</span>
              </div>
              <p style="color:#94a3b8;font-size:0.8rem;margin:0 0 1rem 0;line-height:1.4;">
                ${esc(b.description || 'Intune security baseline enforcing system hardening policies.')}
              </p>
              <div style="font-size:0.8rem;color:#cbd5e1;margin-bottom:0.75rem;">
                <strong>Enforced Hardening Rules (${rules.length}):</strong>
                <ul style="margin:0.4rem 0 0 1.2rem;padding:0;color:#94a3b8;font-size:0.75rem;">
                  ${rules.slice(0, 4).map(r => `<li>${esc(r.name)}</li>`).join('')}
                  ${rules.length > 4 ? `<li>+ ${rules.length - 4} more rules...</li>` : ''}
                </ul>
              </div>
            </div>

            <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid #334155;padding-top:0.75rem;margin-top:0.5rem;">
              <span style="font-size:0.75rem;color:#64748b;">Target: ${esc(b.target_group_name || 'All Workstations')}</span>
              <div style="display:flex;gap:0.4rem;">
                <button class="btn btn-xs btn-inspect-baseline" data-baseline-id="${esc(b.id)}" style="background:#334155;color:#38bdf8;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;">
                  📜 Scripts
                </button>
                <button class="btn btn-xs btn-delete-baseline" data-baseline-id="${esc(b.id)}" style="background:rgba(239,68,68,0.15);color:#ef4444;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;">
                  🗑️
                </button>
              </div>
            </div>
          </div>
        `;
      });
    }

    out += '</div>';
    return out;
  }

  function attachEvents(container) {
    const refreshBtn = container.querySelector('#btn-refresh-tvm');
    if (refreshBtn) refreshBtn.onclick = () => render(container);

    container.querySelectorAll('.btn-subtab').forEach(btn => {
      btn.onclick = () => {
        currentSubTab = btn.getAttribute('data-subtab');
        render(container);
      };
    });

    const searchInput = container.querySelector('#tvm-search-input');
    if (searchInput) {
      searchInput.oninput = (e) => {
        searchQuery = e.target.value;
        const sub = container.querySelector('#tvm-subtab-content');
        if (sub) sub.innerHTML = renderCvesSubtab();
        attachSubtabEvents(container);
      };
    }

    const sevSelect = container.querySelector('#tvm-sev-select');
    if (sevSelect) {
      sevSelect.onchange = (e) => {
        selectedSeverity = e.target.value;
        const sub = container.querySelector('#tvm-subtab-content');
        if (sub) sub.innerHTML = renderCvesSubtab();
        attachSubtabEvents(container);
      };
    }

    const addCveBtn = container.querySelector('#btn-add-cve');
    if (addCveBtn) addCveBtn.onclick = () => showAddCveModal(container);

    const createBaseBtn = container.querySelector('#btn-create-baseline');
    if (createBaseBtn) createBaseBtn.onclick = () => showCreateBaselineModal(container);

    attachSubtabEvents(container);
  }

  function attachSubtabEvents(container) {
    container.querySelectorAll('.btn-view-vuln').forEach(btn => {
      btn.onclick = async () => {
        const cveId = btn.getAttribute('data-cve-id');
        try {
          const res = await window.FleetAPI.getTvmVulnerability(cveId);
          showVulnDetailModal(res.vulnerability);
        } catch (e) {
          alert('Failed to load vulnerability details: ' + e.message);
        }
      };
    });

    container.querySelectorAll('.btn-delete-vuln').forEach(btn => {
      btn.onclick = async () => {
        const cveId = btn.getAttribute('data-cve-id');
        if (confirm('Delete vulnerability ' + cveId + ' from catalog?')) {
          try {
            await window.FleetAPI.deleteTvmVulnerability(cveId);
            render(container);
          } catch (e) {
            alert('Failed to delete vulnerability: ' + e.message);
          }
        }
      };
    });

    container.querySelectorAll('.btn-inspect-baseline').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-baseline-id');
        try {
          const res = await window.FleetAPI.getTvmBaseline(id);
          showBaselineScriptModal(res);
        } catch (e) {
          alert('Failed to load baseline scripts: ' + e.message);
        }
      };
    });

    container.querySelectorAll('.btn-delete-baseline').forEach(btn => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-baseline-id');
        if (confirm('Delete this security baseline template?')) {
          try {
            await window.FleetAPI.deleteTvmBaseline(id);
            render(container);
          } catch (e) {
            alert('Failed to delete baseline: ' + e.message);
          }
        }
      };
    });
  }

  function showVulnDetailModal(vuln) {
    const modalId = 'modal-vuln-detail';
    let existing = document.getElementById(modalId);
    if (existing) existing.remove();

    const devices = vuln.exposed_devices || [];

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:1rem;';
    modal.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;width:100%;max-width:700px;padding:1.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);max-height:90vh;overflow-y:auto;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
          <h3 style="margin:0;color:#f8fafc;font-size:1.15rem;display:flex;align-items:center;gap:0.5rem;">
            <span>🛡️</span> ${esc(vuln.cve_id)} — ${esc(vuln.title)}
          </h3>
          <button id="modal-close-vuln" style="background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer;">✕</button>
        </div>

        <div style="display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;">
          ${getSeverityBadge(vuln.severity)}
          <span class="badge" style="background:rgba(59,130,246,0.15);color:#38bdf8;font-family:monospace;font-weight:700;">CVSS ${vuln.cvss_score.toFixed(1)}</span>
          ${getExploitBadge(vuln.exploit_status)}
          <span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;">${esc(vuln.patch_status)}</span>
        </div>

        <p style="color:#cbd5e1;font-size:0.875rem;line-height:1.5;margin-bottom:1rem;">${esc(vuln.description)}</p>

        <div style="background:#0f172a;border:1px solid #334155;border-radius:6px;padding:0.75rem 1rem;margin-bottom:1rem;font-size:0.85rem;">
          <strong style="color:#38bdf8;">Remediation Recommendation:</strong>
          <div style="color:#94a3b8;margin-top:0.25rem;">${esc(vuln.remediation_guidance || 'Deploy latest security update.')}</div>
        </div>

        <h4 style="color:#f8fafc;margin:1rem 0 0.5rem 0;font-size:0.95rem;">Exposed Workstations (${devices.length})</h4>
        <div style="background:#0f172a;border:1px solid #334155;border-radius:6px;overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:0.8rem;text-align:left;">
            <thead>
              <tr style="border-bottom:1px solid #334155;color:#94a3b8;">
                <th style="padding:0.5rem 0.75rem;">Hostname</th>
                <th style="padding:0.5rem 0.75rem;">Detected Software</th>
                <th style="padding:0.5rem 0.75rem;">Detected Version</th>
                <th style="padding:0.5rem 0.75rem;">Risk</th>
              </tr>
            </thead>
            <tbody>
              ${devices.length === 0 ? '<tr><td colspan="4" style="padding:1rem;text-align:center;color:#64748b;">No client devices currently exposed.</td></tr>' : ''}
              ${devices.map(d => `
                <tr style="border-bottom:1px solid #334155;">
                  <td style="padding:0.5rem 0.75rem;color:#38bdf8;font-weight:600;">${esc(d.hostname)}</td>
                  <td style="padding:0.5rem 0.75rem;color:#cbd5e1;">${esc(d.detected_software_name)}</td>
                  <td style="padding:0.5rem 0.75rem;font-family:monospace;color:#94a3b8;">${esc(d.detected_version)}</td>
                  <td style="padding:0.5rem 0.75rem;color:#ef4444;font-weight:700;">${d.risk_score ? d.risk_score.toFixed(1) : '—'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div style="display:flex;justify-content:flex-end;margin-top:1.2rem;">
          <button id="modal-done-vuln" class="btn btn-primary" style="background:#3b82f6;color:#fff;border:none;padding:0.5rem 1.2rem;border-radius:6px;cursor:pointer;">
            Done
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('#modal-close-vuln').onclick = () => modal.remove();
    modal.querySelector('#modal-done-vuln').onclick = () => modal.remove();
  }

  function showBaselineScriptModal(data) {
    const modalId = 'modal-baseline-script';
    let existing = document.getElementById(modalId);
    if (existing) existing.remove();

    const baseline = data.baseline;
    const auditScript = data.audit_script;
    const remScript = data.remediation_script;

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:1rem;';
    modal.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;width:100%;max-width:720px;padding:1.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);max-height:90vh;overflow-y:auto;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
          <h3 style="margin:0;color:#f8fafc;font-size:1.15rem;display:flex;align-items:center;gap:0.5rem;">
            <span>📜</span> Security Baseline Scripts — ${esc(baseline.name)}
          </h3>
          <button id="modal-close-base-script" style="background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer;">✕</button>
        </div>

        <div style="margin-bottom:1rem;">
          <strong style="color:#38bdf8;font-size:0.85rem;">Compliance Audit Script (PowerShell):</strong>
          <pre style="background:#0f172a;border:1px solid #334155;border-radius:6px;padding:0.75rem;color:#38bdf8;font-size:0.75rem;max-height:160px;overflow-y:auto;margin-top:0.25rem;">${esc(auditScript)}</pre>
        </div>

        <div>
          <strong style="color:#10b981;font-size:0.85rem;">Automated Hardening Remediation Script (PowerShell):</strong>
          <pre style="background:#0f172a;border:1px solid #334155;border-radius:6px;padding:0.75rem;color:#10b981;font-size:0.75rem;max-height:160px;overflow-y:auto;margin-top:0.25rem;">${esc(remScript)}</pre>
        </div>

        <div style="display:flex;justify-content:flex-end;margin-top:1.2rem;">
          <button id="modal-done-base-script" class="btn btn-primary" style="background:#3b82f6;color:#fff;border:none;padding:0.5rem 1.2rem;border-radius:6px;cursor:pointer;">
            Done
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('#modal-close-base-script').onclick = () => modal.remove();
    modal.querySelector('#modal-done-base-script').onclick = () => modal.remove();
  }

  function showAddCveModal(container) {
    const modalId = 'modal-add-cve';
    let existing = document.getElementById(modalId);
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:1rem;';
    modal.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;width:100%;max-width:600px;padding:1.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem;">
          <h3 style="margin:0;color:#f8fafc;font-size:1.1rem;display:flex;align-items:center;gap:0.5rem;">
            <span>➕</span> Add Vulnerability (CVE) to Knowledgebase
          </h3>
          <button id="modal-close-add-cve" style="background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer;">✕</button>
        </div>

        <form id="form-add-cve" style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">CVE Identifier *</label>
            <input type="text" id="add-cve-id" required class="form-control" placeholder="e.g. CVE-2026-31299" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">CVSS v3 Score (0.0 - 10.0) *</label>
            <input type="number" id="add-cve-cvss" required step="0.1" min="0" max="10" value="8.8" class="form-control" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div style="grid-column:span 2;">
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Vulnerability Title *</label>
            <input type="text" id="add-cve-title" required class="form-control" placeholder="e.g. Windows Hyper-V Arbitrary Memory Corruption RCE" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Affected Software *</label>
            <input type="text" id="add-cve-sw" required class="form-control" placeholder="e.g. Windows Hyper-V" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Affected Versions</label>
            <input type="text" id="add-cve-ver" class="form-control" placeholder="e.g. < 22631.4200" value="< 22631.4200" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Exploit Status</label>
            <select id="add-cve-exploit" class="form-control" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
              <option value="NONE">NONE (No known exploit)</option>
              <option value="UNPROVEN">UNPROVEN (Theoretical)</option>
              <option value="ACTIVE_EXPLOIT_POC">ACTIVE_EXPLOIT_POC (Public PoC)</option>
              <option value="WEAPONIZED_WILD">WEAPONIZED_WILD (Exploited in Wild)</option>
            </select>
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Patch Status</label>
            <select id="add-cve-patch" class="form-control" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
              <option value="VENDOR_PATCH_AVAILABLE">VENDOR_PATCH_AVAILABLE</option>
              <option value="MITIGATION_AVAILABLE">MITIGATION_AVAILABLE</option>
              <option value="UNPATCHED">UNPATCHED (Zero-Day)</option>
            </select>
          </div>

          <div style="grid-column:span 2;">
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Remediation Guidance</label>
            <input type="text" id="add-cve-rem" class="form-control" placeholder="e.g. Apply Windows September Security Hotfix" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div style="grid-column:span 2;display:flex;justify-content:flex-end;gap:0.5rem;margin-top:0.75rem;">
            <button type="button" id="modal-cancel-add-cve" class="btn btn-secondary" style="background:#334155;color:#f8fafc;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary" style="background:#ef4444;color:#fff;border:none;padding:0.5rem 1.2rem;border-radius:6px;cursor:pointer;font-weight:600;">
              Record CVE
            </button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('#modal-close-add-cve').onclick = () => modal.remove();
    modal.querySelector('#modal-cancel-add-cve').onclick = () => modal.remove();

    modal.querySelector('#form-add-cve').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        cve_id: document.getElementById('add-cve-id').value,
        cvss_score: parseFloat(document.getElementById('add-cve-cvss').value),
        title: document.getElementById('add-cve-title').value,
        software_name: document.getElementById('add-cve-sw').value,
        affected_versions: document.getElementById('add-cve-ver').value,
        exploit_status: document.getElementById('add-cve-exploit').value,
        patch_status: document.getElementById('add-cve-patch').value,
        remediation_guidance: document.getElementById('add-cve-rem').value
      };

      try {
        await window.FleetAPI.createTvmVulnerability(payload);
        modal.remove();
        render(container);
      } catch (err) {
        alert('Failed to record CVE: ' + err.message);
      }
    };
  }

  function showCreateBaselineModal(container) {
    const modalId = 'modal-create-baseline';
    let existing = document.getElementById(modalId);
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:1rem;';
    modal.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;width:100%;max-width:600px;padding:1.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem;">
          <h3 style="margin:0;color:#f8fafc;font-size:1.1rem;display:flex;align-items:center;gap:0.5rem;">
            <span>➕</span> Create Hardened Security Baseline
          </h3>
          <button id="modal-close-create-base" style="background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer;">✕</button>
        </div>

        <form id="form-create-baseline" style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
          <div style="grid-column:span 2;">
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Baseline Name *</label>
            <input type="text" id="base-name" required class="form-control" placeholder="e.g. Workstation Kernel Isolation Baseline" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Category *</label>
            <select id="base-cat" class="form-control" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
              <option value="OPERATING_SYSTEM">OPERATING_SYSTEM</option>
              <option value="CREDENTIAL_HYGIENE">CREDENTIAL_HYGIENE</option>
              <option value="NETWORK_SECURITY">NETWORK_SECURITY</option>
              <option value="IDENTITY_PROTECTION">IDENTITY_PROTECTION</option>
            </select>
          </div>

          <div>
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Baseline Target Platform</label>
            <input type="text" id="base-type" class="form-control" value="WINDOWS_11_ENTERPRISE" style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;">
          </div>

          <div style="grid-column:span 2;">
            <label style="display:block;color:#cbd5e1;font-size:0.8rem;margin-bottom:0.25rem;">Description</label>
            <textarea id="base-desc" rows="2" class="form-control" placeholder="Detailed description of hardening intent..." style="width:100%;background:#0f172a;border:1px solid #334155;color:#f8fafc;padding:0.5rem;border-radius:6px;"></textarea>
          </div>

          <div style="grid-column:span 2;display:flex;justify-content:flex-end;gap:0.5rem;margin-top:0.75rem;">
            <button type="button" id="modal-cancel-create-base" class="btn btn-secondary" style="background:#334155;color:#f8fafc;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary" style="background:#3b82f6;color:#fff;border:none;padding:0.5rem 1.2rem;border-radius:6px;cursor:pointer;font-weight:600;">
              Save Baseline
            </button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('#modal-close-create-base').onclick = () => modal.remove();
    modal.querySelector('#modal-cancel-create-base').onclick = () => modal.remove();

    modal.querySelector('#form-create-baseline').onsubmit = async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('base-name').value,
        category: document.getElementById('base-cat').value,
        baseline_type: document.getElementById('base-type').value,
        description: document.getElementById('base-desc').value,
        enforcement_rules: [
          {
            id: 'rule-sample-hardening',
            name: 'Enforce Memory Integrity (HVCI)',
            registry_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity',
            value_name: 'Enabled',
            expected_value: 1
          }
        ]
      };

      try {
        await window.FleetAPI.createTvmBaseline(payload);
        modal.remove();
        render(container);
      } catch (err) {
        alert('Failed to create baseline: ' + err.message);
      }
    };
  }

  // Export
  window.VulnerabilitiesTable = {
    render,
    init: render
  };
})();
