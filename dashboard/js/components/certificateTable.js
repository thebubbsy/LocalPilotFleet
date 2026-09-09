/**
 * LocalPilot Fleet — Certificate Management & SCEP/PKCS Blade
 * dashboard/js/components/certificateTable.js
 */

(function () {
  'use strict';

  let currentTab = 'profiles'; // 'profiles' | 'inventory'

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getTypeBadge(type) {
    const map = {
      TRUSTED_ROOT: { bg: 'rgba(16,185,129,0.15)', text: '#10B981', label: '🛡️ Trusted Root' },
      INTERMEDIATE_CA: { bg: 'rgba(59,130,246,0.15)', text: '#60A5FA', label: '🔒 Intermediate CA' },
      SCEP: { bg: 'rgba(245,158,11,0.15)', text: '#F59E0B', label: '🔑 SCEP Profile' },
      PKCS: { bg: 'rgba(168,85,247,0.15)', text: '#C084FC', label: '📦 PKCS (PFX)' }
    };
    const c = map[type] || { bg: 'rgba(148,163,184,0.15)', text: '#94A3B8', label: type };
    return `<span class="badge" style="background:${c.bg};color:${c.text};font-weight:600;">${c.label}</span>`;
  }

  function getStatusBadge(status, days) {
    if (status === 'EXPIRED') {
      return `<span class="badge" style="background:rgba(239,68,68,0.2);color:#EF4444;font-weight:600;">🚨 Expired (${days}d)</span>`;
    }
    if (status === 'EXPIRING_SOON') {
      return `<span class="badge" style="background:rgba(245,158,11,0.2);color:#F59E0B;font-weight:600;">⚠️ Expiring Soon (${days}d)</span>`;
    }
    return `<span class="badge" style="background:rgba(16,185,129,0.15);color:#10B981;font-weight:600;">✔ Valid (${days}d)</span>`;
  }

  async function loadData() {
    const container = document.getElementById('view-certificates');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;color:var(--text-muted);display:flex;align-items:center;gap:12px;">
        <span style="font-size:24px;" class="spin">⏳</span>
        <span>Loading Certificate Governance &amp; SCEP Posture…</span>
      </div>
    `;

    try {
      const [stats, profilesData, inventoryData, groupsData] = await Promise.all([
        window.FleetAPI.getCertificateStats().catch(() => ({})),
        window.FleetAPI.getCertificateProfiles().catch(() => ({ profiles: [] })),
        window.FleetAPI.getCertificateInventory({ limit: 100 }).catch(() => ({ certificates: [] })),
        window.FleetAPI.getDynamicGroups ? window.FleetAPI.getDynamicGroups().catch(() => ({ groups: [] })) : Promise.resolve({ groups: [] })
      ]);

      renderBlade(container, {
        stats,
        profiles: profilesData.profiles || [],
        certificates: inventoryData.certificates || [],
        groups: groupsData.groups || []
      });
    } catch (err) {
      container.innerHTML = `
        <div style="padding:24px;color:var(--accent-red);">
          <h3>Error loading certificate data</h3>
          <p>${esc(err.message)}</p>
          <button class="intune-btn" onclick="window.CertificateTable.init()">Retry</button>
        </div>
      `;
    }
  }

  function renderBlade(container, data) {
    const { stats, profiles, certificates, groups } = data;

    container.innerHTML = `
      <div class="intune-blade-header">
        <div class="intune-breadcrumb">Home &gt; Devices &gt; Certificates &amp; SCEP Profiles</div>
        <div class="intune-title-row">
          <div class="intune-title-icon">📜</div>
          <div>
            <h1 class="intune-blade-title">Certificates &amp; SCEP Profiles</h1>
            <p class="intune-blade-subtitle">
              Microsoft Intune Public Key Infrastructure (PKI) governance, Trusted Root &amp; Intermediate CA deployment, automated SCEP enrollment, and workstation certificate store hygiene.
            </p>
          </div>
        </div>
      </div>

      <!-- KPI Summary Strip -->
      <div class="intune-kpi-strip" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;margin-bottom:20px;">
        <div class="kpi-card" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Active Certificate Profiles</div>
          <div style="font-size:28px;font-weight:700;color:#60A5FA;">${stats.active_profiles ?? 0} <span style="font-size:14px;font-weight:400;color:var(--text-muted);">/ ${stats.total_profiles ?? 0} total</span></div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Root, Intermediate, SCEP &amp; PKCS</div>
        </div>

        <div class="kpi-card" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Managed Workstation Certs</div>
          <div style="font-size:28px;font-weight:700;color:#10B981;">${stats.total_certificates ?? 0}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${stats.valid_count ?? 0} active &amp; valid</div>
        </div>

        <div class="kpi-card" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Expiring Soon (&le; 30 Days)</div>
          <div style="font-size:28px;font-weight:700;color:${(stats.expiring_soon_count || 0) > 0 ? '#F59E0B' : 'var(--text-primary)'};">${stats.expiring_soon_count ?? 0}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">Renewal action advised</div>
        </div>

        <div class="kpi-card" style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:16px;">
          <div style="font-size:12px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Expired / Root CAs</div>
          <div style="font-size:28px;font-weight:700;color:${(stats.expired_count || 0) > 0 ? '#EF4444' : '#10B981'};">${stats.expired_count ?? 0} <span style="font-size:14px;font-weight:400;color:var(--text-muted);">expired</span></div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">${stats.root_cas_count ?? 0} Root Authorities</div>
        </div>
      </div>

      <!-- Action Command Bar -->
      <div class="intune-command-bar" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div style="display:flex;gap:10px;">
          <button class="intune-cmd-btn primary" id="btn-create-cert-profile">
            <span class="cmd-icon">➕</span> Create certificate profile
          </button>
          <button class="intune-cmd-btn" id="btn-refresh-certs">
            <span class="cmd-icon">🔄</span> Refresh
          </button>
        </div>

        <div class="intune-subtabs" style="display:flex;gap:4px;background:rgba(255,255,255,0.05);padding:4px;border-radius:6px;">
          <button class="subtab-btn ${currentTab === 'profiles' ? 'active' : ''}" id="tab-btn-profiles" style="padding:6px 14px;border:none;border-radius:4px;cursor:pointer;background:${currentTab === 'profiles' ? 'var(--accent-primary, #0078d4)' : 'transparent'};color:#fff;font-weight:600;font-size:13px;">
            📜 Certificate Profiles (${profiles.length})
          </button>
          <button class="subtab-btn ${currentTab === 'inventory' ? 'active' : ''}" id="tab-btn-inventory" style="padding:6px 14px;border:none;border-radius:4px;cursor:pointer;background:${currentTab === 'inventory' ? 'var(--accent-primary, #0078d4)' : 'transparent'};color:#fff;font-weight:600;font-size:13px;">
            🔍 Workstation Certificate Inventory (${certificates.length})
          </button>
        </div>
      </div>

      <div id="cert-subtab-content">
        ${currentTab === 'profiles' ? renderProfilesTable(profiles, groups) : renderInventoryTable(certificates)}
      </div>
    `;

    // Bind subtabs
    container.querySelector('#tab-btn-profiles')?.addEventListener('click', () => {
      currentTab = 'profiles';
      loadData();
    });
    container.querySelector('#tab-btn-inventory')?.addEventListener('click', () => {
      currentTab = 'inventory';
      loadData();
    });

    container.querySelector('#btn-refresh-certs')?.addEventListener('click', loadData);
    container.querySelector('#btn-create-cert-profile')?.addEventListener('click', () => showCreateModal(groups));

    // Bind row actions in profiles table
    container.querySelectorAll('.btn-toggle-cert-profile').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const enabled = btn.getAttribute('data-enabled') === '1';
        try {
          await window.FleetAPI.updateCertificateProfile(id, { enabled: !enabled });
          loadData();
        } catch (err) {
          alert(`Failed to update profile: ${err.message}`);
        }
      });
    });

    container.querySelectorAll('.btn-delete-cert-profile').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const name = btn.getAttribute('data-name');
        if (!confirm(`Are you sure you want to delete certificate profile "${name}"?`)) return;
        try {
          await window.FleetAPI.deleteCertificateProfile(id);
          loadData();
        } catch (err) {
          alert(`Failed to delete profile: ${err.message}`);
        }
      });
    });
  }

  function renderProfilesTable(profiles, groups) {
    if (!profiles || profiles.length === 0) {
      return `
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:32px;text-align:center;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">📜</div>
          <h3>No Certificate Profiles Configured</h3>
          <p>Deploy Trusted Root CAs, Intermediate Chains, or SCEP client enrollment profiles across your fleet.</p>
        </div>
      `;
    }

    const groupMap = {};
    if (groups) groups.forEach(g => { groupMap[g.id] = g.name; });

    const rows = profiles.map(p => {
      const groupName = p.target_group_id === 'grp-all' ? 'All Managed Workstations' : (groupMap[p.target_group_id] || p.target_group_id);
      const isEnabled = p.enabled === 1;

      return `
        <tr style="border-bottom:1px solid #1e293b;">
          <td style="padding:12px 14px;">
            <div style="font-weight:600;color:var(--text-primary);">${esc(p.name)}</div>
            <div style="font-size:12px;color:var(--text-muted);">${esc(p.description || 'No description')}</div>
            ${p.scep_server_url ? `<div style="font-size:11px;color:#60A5FA;margin-top:2px;">🌐 SCEP: ${esc(p.scep_server_url)}</div>` : ''}
          </td>
          <td style="padding:12px 14px;">${getTypeBadge(p.certificate_type)}</td>
          <td style="padding:12px 14px;font-size:12px;font-family:monospace;color:var(--text-muted);">
            ${esc(p.target_store)}
          </td>
          <td style="padding:12px 14px;font-size:13px;color:var(--text-muted);">
            <span class="badge" style="background:rgba(255,255,255,0.06);">${esc(groupName)}</span>
          </td>
          <td style="padding:12px 14px;font-size:12px;color:var(--text-muted);">
            ${p.validity_period_days} days (${p.key_storage_provider} ${p.key_size}-bit)
          </td>
          <td style="padding:12px 14px;">
            <span class="badge" style="background:${isEnabled ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'};color:${isEnabled ? '#10B981' : '#EF4444'};">
              ${isEnabled ? '● Active' : '○ Disabled'}
            </span>
          </td>
          <td style="padding:12px 14px;text-align:right;">
            <button class="intune-btn btn-toggle-cert-profile" data-id="${esc(p.id)}" data-enabled="${p.enabled}" style="padding:4px 10px;font-size:12px;margin-right:6px;">
              ${isEnabled ? 'Disable' : 'Enable'}
            </button>
            <button class="intune-btn delete btn-delete-cert-profile" data-id="${esc(p.id)}" data-name="${esc(p.name)}" style="padding:4px 10px;font-size:12px;">
              Delete
            </button>
          </td>
        </tr>
      `;
    }).join('');

    return `
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid #334155;background:rgba(255,255,255,0.02);color:var(--text-muted);">
              <th style="padding:12px 14px;">PROFILE NAME</th>
              <th style="padding:12px 14px;">TYPE</th>
              <th style="padding:12px 14px;">TARGET STORE</th>
              <th style="padding:12px 14px;">ASSIGNMENT</th>
              <th style="padding:12px 14px;">VALIDITY / KEY</th>
              <th style="padding:12px 14px;">STATUS</th>
              <th style="padding:12px 14px;text-align:right;">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderInventoryTable(certificates) {
    if (!certificates || certificates.length === 0) {
      return `
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:32px;text-align:center;color:var(--text-muted);">
          <div style="font-size:32px;margin-bottom:8px;">🔍</div>
          <h3>No Workstation Certificates Scanned</h3>
          <p>Managed workstations automatically report their certificate stores during agent check-in.</p>
        </div>
      `;
    }

    const rows = certificates.map(c => {
      const expDate = c.not_after ? new Date(c.not_after).toLocaleDateString() : '—';
      return `
        <tr style="border-bottom:1px solid #1e293b;">
          <td style="padding:12px 14px;">
            <div style="font-weight:600;color:var(--text-primary);">${esc(c.subject)}</div>
            <div style="font-size:11px;color:var(--text-muted);">Issuer: ${esc(c.issuer)}</div>
            <div style="font-size:10px;font-family:monospace;color:#64748B;margin-top:2px;" title="${esc(c.thumbprint)}">SHA1: ${esc(c.thumbprint.slice(0, 16))}…</div>
          </td>
          <td style="padding:12px 14px;">
            <span style="font-weight:600;color:#60A5FA;">💻 ${esc(c.hostname || 'Unknown')}</span>
            ${c.primary_user ? `<div style="font-size:11px;color:var(--text-muted);">👤 ${esc(c.primary_user)}</div>` : ''}
          </td>
          <td style="padding:12px 14px;font-size:12px;color:var(--text-muted);">
            <div>${esc(c.store_location)}</div>
            <div style="font-size:11px;color:#94A3B8;">📁 ${esc(c.store_name)}</div>
          </td>
          <td style="padding:12px 14px;font-size:12px;color:var(--text-muted);">
            ${expDate}
          </td>
          <td style="padding:12px 14px;">
            ${getStatusBadge(c.status, c.days_to_expiry)}
          </td>
          <td style="padding:12px 14px;text-align:center;">
            ${c.has_private_key ? '<span title="Private Key Present" style="color:#10B981;font-size:15px;">🔑 Yes</span>' : '<span style="color:#64748B;font-size:12px;">No</span>'}
          </td>
        </tr>
      `;
    }).join('');

    return `
      <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;text-align:left;font-size:13px;">
          <thead>
            <tr style="border-bottom:1px solid #334155;background:rgba(255,255,255,0.02);color:var(--text-muted);">
              <th style="padding:12px 14px;">CERTIFICATE SUBJECT &amp; ISSUER</th>
              <th style="padding:12px 14px;">WORKSTATION</th>
              <th style="padding:12px 14px;">STORE</th>
              <th style="padding:12px 14px;">EXPIRY DATE</th>
              <th style="padding:12px 14px;">HEALTH</th>
              <th style="padding:12px 14px;text-align:center;">PRIVATE KEY</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    `;
  }

  function showCreateModal(groups) {
    let modal = document.getElementById('create-cert-profile-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'create-cert-profile-modal';
      modal.className = 'modal-backdrop';
      document.body.appendChild(modal);
    }

    const groupOptions = (groups || []).map(g => `<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('');

    modal.innerHTML = `
      <div class="modal-card" style="max-width:620px;background:#0f172a;border:1px solid #334155;border-radius:10px;padding:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <h3 style="margin:0;font-size:18px;color:var(--text-primary);">📜 Create Certificate Profile</h3>
          <button class="close-btn" id="btn-close-cert-modal" style="background:transparent;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;">✕</button>
        </div>

        <!-- Enterprise Presets Strip -->
        <div style="margin-bottom:16px;padding:12px;background:rgba(255,255,255,0.03);border:1px solid #334155;border-radius:6px;">
          <div style="font-size:11px;font-weight:600;color:var(--text-muted);margin-bottom:8px;text-transform:uppercase;">⚡ Quick Apply Enterprise Presets</div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="intune-btn" id="preset-root-ca" style="font-size:12px;padding:4px 10px;">🛡️ Trusted Root CA</button>
            <button class="intune-btn" id="preset-scep" style="font-size:12px;padding:4px 10px;">🔑 Workstation SCEP</button>
            <button class="intune-btn" id="preset-intermediate" style="font-size:12px;padding:4px 10px;">🔒 Intermediate SubCA</button>
          </div>
        </div>

        <div style="display:flex;flex-direction:column;gap:12px;max-height:65vh;overflow-y:auto;padding-right:4px;">
          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">PROFILE NAME *</label>
            <input id="modal-cert-name" class="intune-input" type="text" style="width:100%;box-sizing:border-box;" placeholder="e.g. Enterprise Root CA">
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">DESCRIPTION</label>
            <textarea id="modal-cert-desc" class="intune-input" rows="2" style="width:100%;box-sizing:border-box;font-family:inherit;" placeholder="Describe profile purpose and target service..."></textarea>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">CERTIFICATE TYPE</label>
              <select id="modal-cert-type" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="TRUSTED_ROOT">🛡️ Trusted Root Certificate</option>
                <option value="INTERMEDIATE_CA">🔒 Intermediate CA Certificate</option>
                <option value="SCEP">🔑 SCEP Certificate Profile</option>
                <option value="PKCS">📦 PKCS / PFX Certificate Profile</option>
              </select>
            </div>

            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">TARGET STORE</label>
              <select id="modal-cert-store" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="LOCAL_MACHINE_ROOT">Computer: Trusted Root (Root)</option>
                <option value="LOCAL_MACHINE_CA">Computer: Intermediate CA (CA)</option>
                <option value="LOCAL_MACHINE_MY">Computer: Personal (My)</option>
                <option value="CURRENT_USER_MY">User: Personal (My)</option>
              </select>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">TARGET DYNAMIC GROUP</label>
              <select id="modal-cert-group" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="grp-all">All Managed Workstations</option>
                ${groupOptions}
              </select>
            </div>

            <div>
              <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">KEY SPECIFICATION</label>
              <select id="modal-cert-key" class="intune-input" style="width:100%;box-sizing:border-box;">
                <option value="2048">RSA 2048-bit</option>
                <option value="4096">RSA 4096-bit (High Security)</option>
              </select>
            </div>
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">SUBJECT NAME FORMAT</label>
            <input id="modal-cert-subject" class="intune-input" type="text" style="width:100%;box-sizing:border-box;" placeholder="CN={{DeviceName}}, O=LocalPilot Fleet">
          </div>

          <div id="modal-scep-group">
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">SCEP SERVER URL (NDES / MSCEP)</label>
            <input id="modal-cert-scep" class="intune-input" type="url" style="width:100%;box-sizing:border-box;" placeholder="https://ca.corp.internal/certsrv/mscep/mscep.dll">
          </div>

          <div>
            <label style="display:block;font-size:12px;font-weight:600;color:var(--text-muted);margin-bottom:4px;">CERTIFICATE DATA (BASE64 CER / PEM / CRT)</label>
            <textarea id="modal-cert-data" class="intune-input" rows="3" style="width:100%;box-sizing:border-box;font-family:monospace;font-size:11px;" placeholder="Paste Base64 encoded certificate binary or public key..."></textarea>
          </div>
        </div>

        <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:20px;">
          <button class="intune-btn" id="btn-cancel-cert-modal">Cancel</button>
          <button class="intune-btn primary" id="btn-save-cert-profile">Save &amp; Assign Profile</button>
        </div>
      </div>
    `;

    modal.style.display = 'flex';

    // Preset handlers
    modal.querySelector('#preset-root-ca')?.addEventListener('click', () => {
      modal.querySelector('#modal-cert-name').value = 'Enterprise Zero-Trust Root CA';
      modal.querySelector('#modal-cert-desc').value = 'Distributes enterprise trusted root certificate for zero-trust TLS inspection and VPN.';
      modal.querySelector('#modal-cert-type').value = 'TRUSTED_ROOT';
      modal.querySelector('#modal-cert-store').value = 'LOCAL_MACHINE_ROOT';
      modal.querySelector('#modal-cert-key').value = '4096';
      modal.querySelector('#modal-cert-subject').value = 'CN=LocalPilot Fleet Root CA, O=LocalPilot Security';
      modal.querySelector('#modal-cert-scep').value = '';
    });

    modal.querySelector('#preset-scep')?.addEventListener('click', () => {
      modal.querySelector('#modal-cert-name').value = 'Workstation SCEP Wi-Fi & VPN Auth';
      modal.querySelector('#modal-cert-desc').value = 'Automated client certificate enrollment for 802.1X enterprise network security.';
      modal.querySelector('#modal-cert-type').value = 'SCEP';
      modal.querySelector('#modal-cert-store').value = 'LOCAL_MACHINE_MY';
      modal.querySelector('#modal-cert-key').value = '2048';
      modal.querySelector('#modal-cert-subject').value = 'CN={{DeviceName}}, OU=Workstations, O=LocalPilot Fleet';
      modal.querySelector('#modal-cert-scep').value = 'https://ca.localpilot.internal/certsrv/mscep/mscep.dll';
    });

    modal.querySelector('#preset-intermediate')?.addEventListener('click', () => {
      modal.querySelector('#modal-cert-name').value = 'Internal Services Intermediate CA';
      modal.querySelector('#modal-cert-desc').value = 'Intermediate certificate authority chain for hybrid cloud and internal microservices.';
      modal.querySelector('#modal-cert-type').value = 'INTERMEDIATE_CA';
      modal.querySelector('#modal-cert-store').value = 'LOCAL_MACHINE_CA';
      modal.querySelector('#modal-cert-key').value = '4096';
      modal.querySelector('#modal-cert-subject').value = 'CN=LocalPilot Issuing SubCA, O=LocalPilot Security';
      modal.querySelector('#modal-cert-scep').value = '';
    });

    modal.querySelector('#btn-close-cert-modal')?.addEventListener('click', () => modal.style.display = 'none');
    modal.querySelector('#btn-cancel-cert-modal')?.addEventListener('click', () => modal.style.display = 'none');

    modal.querySelector('#btn-save-cert-profile')?.addEventListener('click', async () => {
      const name = modal.querySelector('#modal-cert-name').value.trim();
      if (!name) {
        alert('Please provide a profile name.');
        return;
      }

      const payload = {
        name,
        description: modal.querySelector('#modal-cert-desc').value.trim(),
        certificateType: modal.querySelector('#modal-cert-type').value,
        targetStore: modal.querySelector('#modal-cert-store').value,
        targetGroupId: modal.querySelector('#modal-cert-group').value,
        keySize: parseInt(modal.querySelector('#modal-cert-key').value, 10),
        subjectName: modal.querySelector('#modal-cert-subject').value.trim(),
        scepServerUrl: modal.querySelector('#modal-cert-scep').value.trim(),
        certificateDataBase64: modal.querySelector('#modal-cert-data').value.trim()
      };

      try {
        await window.FleetAPI.createCertificateProfile(payload);
        modal.style.display = 'none';
        if (typeof showToast === 'function') showToast('Profile Created', `Certificate profile "${name}" successfully deployed.`, 'success');
        loadData();
      } catch (err) {
        alert(`Failed to create certificate profile: ${err.message}`);
      }
    });
  }

  window.CertificateTable = {
    init: loadData,
    refresh: loadData
  };
})();
