/**
 * LocalPilot Fleet — Enterprise PKI Code-Signing Authority & Digital Payload Verification Blade
 * dashboard/js/components/pkiSigningTable.js
 *
 * Dimension 3: Cryptographic Identity, Zero Trust & Tamper Resistance
 */

(function () {
  'use strict';

  let currentSubTab = 'keys'; // 'keys' | 'manifests' | 'studio'
  let cachedStats = null;
  let cachedKeys = [];
  let cachedManifests = [];
  let searchQuery = '';
  let studioPayload = '# Sample Zero-Trust Remediation Script\r\nGet-Service -Name "wuauserv" | Restart-Service -Force\r\nWrite-Output "Windows Update Service Restarted"';
  let studioSignedResult = null;
  let studioVerifyResult = null;

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getKeyBadge(key) {
    if (key.is_revoked) {
      return '<span class="badge" style="background:rgba(239,68,68,0.2);color:#ef4444;font-weight:700;border:1px solid #ef444444;">🚫 REVOKED</span>';
    }
    if (key.is_active) {
      return '<span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;font-weight:700;border:1px solid #10b98144;">🛡️ ACTIVE ROOT CA</span>';
    }
    return '<span class="badge" style="background:rgba(107,114,128,0.15);color:#94a3b8;">INACTIVE</span>';
  }

  function getTypeBadge(type) {
    const t = String(type || 'SCRIPT').toUpperCase();
    const colors = {
      SCRIPT: '#3b82f6',
      REMEDIATION: '#10b981',
      PACKAGE: '#8b5cf6',
      BASELINE: '#f59e0b',
      CONFIG_PROFILE: '#ec4899'
    };
    const c = colors[t] || '#6b7280';
    return `<span class="badge" style="background:${c}22;color:${c};font-weight:600;border:1px solid ${c}44;">${esc(t)}</span>`;
  }

  async function loadData() {
    try {
      const [stats, keysData, manifestsData] = await Promise.all([
        window.FleetAPI.getPkiStats().catch(() => ({})),
        window.FleetAPI.getSigningKeys().catch(() => ({ keys: [] })),
        window.FleetAPI.getSigningManifests({ limit: 100 }).catch(() => ({ manifests: [] }))
      ]);

      cachedStats = stats || {};
      cachedKeys = keysData.keys || [];
      cachedManifests = manifestsData.manifests || [];
      render();
    } catch (err) {
      console.error('Failed to load PKI data:', err);
    }
  }

  function renderKpiCards() {
    if (!cachedStats) return '';
    const auth = cachedStats.active_authority || {};
    const thumbShort = auth.thumbprint ? auth.thumbprint.substring(0, 16) + '...' : 'None';

    return `
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:14px;margin-bottom:20px;">
        <div class="card" style="padding:16px;border-left:4px solid #10b981;">
          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;font-weight:700;">Code-Signing Authority</div>
          <div style="font-size:22px;font-weight:700;color:#f8fafc;margin:6px 0 2px;">${cachedStats.status === 'OPERATIONAL' ? '🛡️ Operational' : '⚠️ No Authority'}</div>
          <div style="font-size:11px;color:#38bdf8;font-family:monospace;" title="${esc(auth.thumbprint || '')}">SHA256: ${esc(thumbShort)}</div>
        </div>
        <div class="card" style="padding:16px;border-left:4px solid #3b82f6;">
          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;font-weight:700;">Total Signing Keys</div>
          <div style="font-size:24px;font-weight:700;color:#f8fafc;margin:4px 0;">${cachedStats.total_keys || 0}</div>
          <div style="font-size:12px;color:#94a3b8;">${cachedStats.active_keys || 0} Active &bull; ${cachedStats.revoked_keys || 0} Revoked</div>
        </div>
        <div class="card" style="padding:16px;border-left:4px solid #8b5cf6;">
          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;font-weight:700;">Signed Payloads</div>
          <div style="font-size:24px;font-weight:700;color:#f8fafc;margin:4px 0;">${cachedStats.total_signed_manifests || 0}</div>
          <div style="font-size:12px;color:#94a3b8;">Cryptographically Envelope Protected</div>
        </div>
        <div class="card" style="padding:16px;border-left:4px solid #f59e0b;">
          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;font-weight:700;">Zero-Trust Tamper Gate</div>
          <div style="font-size:22px;font-weight:700;color:#10b981;margin:4px 0;">🔒 100% Enforced</div>
          <div style="font-size:12px;color:#94a3b8;">RSA-SHA256 Pre-Execution Check</div>
        </div>
      </div>
    `;
  }

  function renderSubTabs() {
    return `
      <div style="display:flex;gap:8px;border-bottom:1px solid #334155;padding-bottom:10px;margin-bottom:16px;">
        <button id="pki-subtab-keys" class="btn ${currentSubTab === 'keys' ? 'btn-primary' : 'btn-secondary'}" style="font-size:13px;padding:6px 14px;">
          🔑 Authority Keys (${cachedKeys.length})
        </button>
        <button id="pki-subtab-manifests" class="btn ${currentSubTab === 'manifests' ? 'btn-primary' : 'btn-secondary'}" style="font-size:13px;padding:6px 14px;">
          📜 Signed Manifests Audit (${cachedManifests.length})
        </button>
        <button id="pki-subtab-studio" class="btn ${currentSubTab === 'studio' ? 'btn-primary' : 'btn-secondary'}" style="font-size:13px;padding:6px 14px;">
          ⚡ Zero-Trust Verification Studio
        </button>
      </div>
    `;
  }

  function renderKeysTable() {
    if (!cachedKeys.length) {
      return '<div style="padding:32px;text-align:center;color:#94a3b8;">No signing keys found. Generate or rotate a key above.</div>';
    }

    return `
      <div class="table-container">
        <table class="table" style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="border-bottom:1px solid #334155;text-align:left;color:#94a3b8;font-size:12px;text-transform:uppercase;">
              <th style="padding:10px 12px;">Key ID / Name</th>
              <th style="padding:10px 12px;">Algorithm</th>
              <th style="padding:10px 12px;">Status</th>
              <th style="padding:10px 12px;">Public Thumbprint</th>
              <th style="padding:10px 12px;">Payloads Signed</th>
              <th style="padding:10px 12px;">Expires</th>
              <th style="padding:10px 12px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${cachedKeys.map(k => `
              <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:12px;">
                  <div style="font-weight:600;color:#f8fafc;">${esc(k.name)}</div>
                  <div style="font-size:11px;color:#94a3b8;font-family:monospace;">${esc(k.id)}</div>
                </td>
                <td style="padding:12px;"><span class="badge" style="background:#1e293b;color:#38bdf8;">${esc(k.key_type)}</span></td>
                <td style="padding:12px;">${getKeyBadge(k)}</td>
                <td style="padding:12px;">
                  <span style="font-family:monospace;font-size:11px;color:#cbd5e1;background:#0f172a;padding:4px 8px;border-radius:4px;" title="${esc(k.thumbprint)}">
                    ${esc(k.thumbprint.substring(0, 16))}...
                  </span>
                </td>
                <td style="padding:12px;color:#f8fafc;font-weight:600;">${k.signed_count || 0}</td>
                <td style="padding:12px;font-size:12px;color:#94a3b8;">${esc(k.expires_at || 'Never')}</td>
                <td style="padding:12px;text-align:right;">
                  <button class="btn btn-secondary btn-sm pki-view-pem-btn" data-id="${esc(k.id)}" style="font-size:11px;padding:4px 8px;margin-right:4px;">📜 View PEM</button>
                  ${!k.is_revoked ? `
                    <button class="btn btn-danger btn-sm pki-revoke-btn" data-id="${esc(k.id)}" style="font-size:11px;padding:4px 8px;">🚫 Revoke</button>
                  ` : ''}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderManifestsTable() {
    let filtered = cachedManifests;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(m =>
        (m.id && m.id.toLowerCase().includes(q)) ||
        (m.payload_type && m.payload_type.toLowerCase().includes(q)) ||
        (m.target_id && m.target_id.toLowerCase().includes(q)) ||
        (m.sha256_hash && m.sha256_hash.toLowerCase().includes(q))
      );
    }

    return `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <input type="text" id="pki-manifest-search" class="input" placeholder="Search by manifest ID, type, target, hash..." value="${esc(searchQuery)}" style="width:320px;font-size:13px;padding:6px 10px;" />
        <div style="font-size:12px;color:#94a3b8;">Showing ${filtered.length} of ${cachedManifests.length} manifests</div>
      </div>
      <div class="table-container">
        <table class="table" style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="border-bottom:1px solid #334155;text-align:left;color:#94a3b8;font-size:12px;text-transform:uppercase;">
              <th style="padding:10px 12px;">Manifest ID</th>
              <th style="padding:10px 12px;">Type</th>
              <th style="padding:10px 12px;">Target ID</th>
              <th style="padding:10px 12px;">SHA-256 Digest</th>
              <th style="padding:10px 12px;">Signer Authority</th>
              <th style="padding:10px 12px;">Signed At</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.length === 0 ? '<tr><td colspan="6" style="padding:24px;text-align:center;color:#94a3b8;">No manifests match search</td></tr>' : ''}
            ${filtered.map(m => `
              <tr style="border-bottom:1px solid #1e293b;">
                <td style="padding:12px;font-family:monospace;font-size:12px;color:#38bdf8;">${esc(m.id)}</td>
                <td style="padding:12px;">${getTypeBadge(m.payload_type)}</td>
                <td style="padding:12px;font-size:12px;color:#f8fafc;">${esc(m.target_id || '(Direct/Interactive)')}</td>
                <td style="padding:12px;">
                  <span style="font-family:monospace;font-size:11px;color:#94a3b8;" title="${esc(m.sha256_hash)}">
                    ${esc(m.sha256_hash.substring(0, 16))}...
                  </span>
                </td>
                <td style="padding:12px;">
                  <div style="font-size:12px;color:#f8fafc;">${esc(m.key_name || m.key_id)}</div>
                  <div style="font-size:11px;color:#64748b;font-family:monospace;">${esc((m.signer_thumbprint || '').substring(0, 12))}...</div>
                </td>
                <td style="padding:12px;font-size:12px;color:#94a3b8;">${esc(m.signed_at || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderStudio() {
    return `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
        <div class="card" style="padding:16px;">
          <div style="font-weight:700;color:#f8fafc;margin-bottom:8px;font-size:14px;">1. Payload & Digital Signing</div>
          <div style="font-size:12px;color:#94a3b8;margin-bottom:10px;">Paste PowerShell script or remediation payload. The authority signs the payload and appends a tamper-proof digital signature envelope.</div>
          <textarea id="pki-studio-input" class="input" style="width:100%;height:180px;font-family:monospace;font-size:12px;resize:vertical;margin-bottom:12px;">${esc(studioPayload)}</textarea>
          <div style="display:flex;gap:8px;">
            <button id="pki-studio-sign-btn" class="btn btn-primary" style="font-size:13px;">✍️ Cryptographically Sign Payload</button>
            <button id="pki-studio-tamper-btn" class="btn btn-secondary" style="font-size:13px;" ${!studioSignedResult ? 'disabled' : ''}>⚠️ Inject Attacker Tamper</button>
          </div>
        </div>

        <div class="card" style="padding:16px;">
          <div style="font-weight:700;color:#f8fafc;margin-bottom:8px;font-size:14px;">2. Zero-Trust Verification Gate</div>
          <div style="font-size:12px;color:#94a3b8;margin-bottom:10px;">Enforces signature validation. If content is modified by even 1 bit or key is revoked, the zero-trust gate rejects execution.</div>
          
          <div id="pki-studio-output" style="background:#0f172a;border:1px solid #1e293b;border-radius:6px;padding:12px;height:180px;overflow:auto;font-family:monospace;font-size:11px;color:#cbd5e1;white-space:pre-wrap;margin-bottom:12px;">${
            studioSignedResult ? esc(studioSignedResult.wrapped_script) : '// Signed script with signature envelope will appear here...'
          }</div>

          <div style="display:flex;gap:8px;align-items:center;">
            <button id="pki-studio-verify-btn" class="btn btn-success" style="font-size:13px;" ${!studioSignedResult ? 'disabled' : ''}>🔍 Verify Authentic Signature</button>
            <div id="pki-studio-status-box"></div>
          </div>
        </div>
      </div>
    `;
  }

  function render() {
    const container = document.getElementById('pki-blade-content');
    if (!container) return;

    container.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div>
          <h2 style="margin:0;font-size:20px;font-weight:700;color:#f8fafc;display:flex;align-items:center;gap:8px;">
            <span>🛡️ Enterprise PKI Code-Signing Authority</span>
            <span class="badge" style="background:rgba(16,185,129,0.15);color:#10b981;font-size:11px;">DIMENSION 3: ZERO-TRUST</span>
          </h2>
          <div style="font-size:12px;color:#94a3b8;margin-top:4px;">
            Asymmetric RSA Cryptographic Identity, Payload Signatures & Tamper-Resistant Execution Gates
          </div>
        </div>
        <div style="display:flex;gap:8px;">
          <button id="pki-rotate-key-btn" class="btn btn-secondary" style="font-size:12px;">🔄 Rotate Root Authority</button>
          <button id="pki-generate-key-btn" class="btn btn-secondary" style="font-size:12px;">➕ New Key</button>
          <button id="pki-export-cert-btn" class="btn btn-primary" style="font-size:12px;">📥 Export CA Public Key</button>
        </div>
      </div>

      ${renderKpiCards()}
      ${renderSubTabs()}

      <div id="pki-subtab-container">
        ${currentSubTab === 'keys' ? renderKeysTable() : ''}
        ${currentSubTab === 'manifests' ? renderManifestsTable() : ''}
        ${currentSubTab === 'studio' ? renderStudio() : ''}
      </div>
    `;

    bindEvents();
  }

  function bindEvents() {
    const subtabKeys = document.getElementById('pki-subtab-keys');
    const subtabManifests = document.getElementById('pki-subtab-manifests');
    const subtabStudio = document.getElementById('pki-subtab-studio');

    if (subtabKeys) subtabKeys.addEventListener('click', () => { currentSubTab = 'keys'; render(); });
    if (subtabManifests) subtabManifests.addEventListener('click', () => { currentSubTab = 'manifests'; render(); });
    if (subtabStudio) subtabStudio.addEventListener('click', () => { currentSubTab = 'studio'; render(); });

    const searchInput = document.getElementById('pki-manifest-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value;
        const cont = document.getElementById('pki-subtab-container');
        if (cont && currentSubTab === 'manifests') cont.innerHTML = renderManifestsTable();
      });
    }

    // View PEM buttons
    document.querySelectorAll('.pki-view-pem-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        const key = cachedKeys.find(k => k.id === id);
        if (key) showPemModal(key);
      });
    });

    // Revoke buttons
    document.querySelectorAll('.pki-revoke-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const reason = prompt('Enter revocation reason for key ' + id + ':');
        if (reason) {
          try {
            await window.FleetAPI.revokeSigningKey(id, reason);
            alert('Key revoked successfully.');
            loadData();
          } catch (err) {
            alert('Revocation failed: ' + err.message);
          }
        }
      });
    });

    // Rotate Key
    const rotateBtn = document.getElementById('pki-rotate-key-btn');
    if (rotateBtn) {
      rotateBtn.addEventListener('click', async () => {
        if (confirm('Rotate active fleet code-signing authority key? Older keys will remain valid for legacy signatures unless explicitly revoked.')) {
          try {
            await window.FleetAPI.rotateSigningKey();
            alert('Root Code-Signing Authority rotated successfully!');
            loadData();
          } catch (err) {
            alert('Key rotation failed: ' + err.message);
          }
        }
      });
    }

    // Generate Key
    const genBtn = document.getElementById('pki-generate-key-btn');
    if (genBtn) {
      genBtn.addEventListener('click', async () => {
        const name = prompt('Enter name for the new signing key:', 'Secondary Code-Signing Authority');
        if (name) {
          try {
            await window.FleetAPI.generateSigningKey({ name, keyType: 'RSA-2048', setAsActive: false });
            alert('Key generated successfully.');
            loadData();
          } catch (err) {
            alert('Key generation failed: ' + err.message);
          }
        }
      });
    }

    // Export CA Public Key
    const exportBtn = document.getElementById('pki-export-cert-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', async () => {
        try {
          const cert = await window.FleetAPI.getPublicPkiCert();
          showPemModal({ name: cert.name, public_key_pem: cert.public_key_pem, thumbprint: cert.thumbprint, id: cert.key_id });
        } catch (err) {
          alert('Export failed: ' + err.message);
        }
      });
    }

    // Studio: Sign
    const studioSignBtn = document.getElementById('pki-studio-sign-btn');
    if (studioSignBtn) {
      studioSignBtn.addEventListener('click', async () => {
        const inputArea = document.getElementById('pki-studio-input');
        studioPayload = inputArea ? inputArea.value : '';
        try {
          studioSignedResult = await window.FleetAPI.signPayload({
            payload: studioPayload,
            payload_type: 'SCRIPT',
            wrap_envelope: true
          });
          studioVerifyResult = null;
          render();
        } catch (err) {
          alert('Signing failed: ' + err.message);
        }
      });
    }

    // Studio: Tamper
    const studioTamperBtn = document.getElementById('pki-studio-tamper-btn');
    if (studioTamperBtn) {
      studioTamperBtn.addEventListener('click', () => {
        if (!studioSignedResult) return;
        studioSignedResult.wrapped_script = studioSignedResult.wrapped_script.replace('Restart-Service', 'Remove-Item -Recurse C:\* # MALICIOUS INJECTION');
        render();
      });
    }

    // Studio: Verify
    const studioVerifyBtn = document.getElementById('pki-studio-verify-btn');
    if (studioVerifyBtn) {
      studioVerifyBtn.addEventListener('click', async () => {
        if (!studioSignedResult) return;
        try {
          studioVerifyResult = await window.FleetAPI.verifyPayload({
            envelope_text: studioSignedResult.wrapped_script
          });
          const statusBox = document.getElementById('pki-studio-status-box');
          if (statusBox) {
            if (studioVerifyResult.valid) {
              statusBox.innerHTML = '<span class="badge" style="background:#10b98133;color:#10b981;font-weight:700;padding:6px 12px;border:1px solid #10b98166;">✅ VERIFIED AUTHENTIC & UNTAMPERED</span>';
            } else {
              statusBox.innerHTML = `<span class="badge" style="background:#ef444433;color:#ef4444;font-weight:700;padding:6px 12px;border:1px solid #ef444466;">🚫 BLOCKED: ${esc(studioVerifyResult.error)}</span>`;
            }
          }
        } catch (err) {
          alert('Verification call failed: ' + err.message);
        }
      });
    }
  }

  function showPemModal(key) {
    const existing = document.getElementById('pki-pem-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'pki-pem-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
      <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;width:640px;max-width:90vw;padding:24px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
          <div style="font-weight:700;font-size:16px;color:#f8fafc;">📜 Public Key (SPKI PEM) & Certificate</div>
          <button id="pki-close-pem-modal" style="background:transparent;border:none;color:#94a3b8;font-size:20px;cursor:pointer;">&times;</button>
        </div>
        <div style="font-size:12px;color:#94a3b8;margin-bottom:8px;">${esc(key.name)} (${esc(key.id)})</div>
        <div style="font-size:11px;color:#38bdf8;font-family:monospace;margin-bottom:12px;word-break:break-all;">SHA-256 Thumbprint: ${esc(key.thumbprint)}</div>
        <textarea readonly style="width:100%;height:220px;background:#0f172a;color:#10b981;border:1px solid #334155;border-radius:4px;padding:10px;font-family:monospace;font-size:11px;resize:none;">${esc(key.public_key_pem)}</textarea>
        <div style="margin-top:16px;display:flex;justify-content:flex-end;gap:8px;">
          <button id="pki-copy-pem-btn" class="btn btn-secondary" style="font-size:12px;">📋 Copy PEM</button>
          <button id="pki-dismiss-pem-btn" class="btn btn-primary" style="font-size:12px;">Done</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    document.getElementById('pki-close-pem-modal').onclick = () => modal.remove();
    document.getElementById('pki-dismiss-pem-btn').onclick = () => modal.remove();
    document.getElementById('pki-copy-pem-btn').onclick = () => {
      navigator.clipboard.writeText(key.public_key_pem);
      alert('Public Key PEM copied to clipboard!');
    };
  }

  window.PkiSigningTable = {
    render: () => {
      loadData();
    },
    refresh: () => {
      loadData();
    }
  };
})();
