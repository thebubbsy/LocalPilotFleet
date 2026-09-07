/**
 * LocalPilot Fleet — BitLocker Drive Encryption & Recovery Vault UI Blade
 * dashboard/js/components/bitlockerTable.js
 *
 * Implements Microsoft Intune BitLocker Key Escrow & Disk Encryption interface:
 * - Executive KPI summary strip & fleet encryption metrics
 * - Sub-blades: Recovery Key Vault, Encryption Policies, Key Access Audit Log
 * - Tamper-evident key reveal with compliance paper trail
 * - Remote key rotation and silent drive encryption dispatch
 * - Policy creation wizard with enterprise presets
 */

(function () {
  'use strict';

  function esc(v) {
    return String(v ?? '—')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  let _activeSubTab = 'vault'; // 'vault' | 'policies' | 'audit'
  let _bitlockerStats = null;
  let _recoveryKeys = [];
  let _policies = [];
  let _auditLogs = [];
  let _groups = [];
  let _searchQuery = '';

  async function loadData() {
    const container = document.getElementById('view-bitlocker');
    if (!container) return;

    container.innerHTML = `
      <div style="padding:24px;">
        <div class="skeleton skeleton-text" style="width:250px;height:24px;margin-bottom:12px;"></div>
        <div class="skeleton skeleton-text" style="width:400px;height:16px;margin-bottom:24px;"></div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
          ${[...Array(4)].map(() => '<div class="skeleton skeleton-card" style="height:90px;"></div>').join('')}
        </div>
      </div>
    `;

    try {
      const [stats, keysData, policiesData, auditData, groups] = await Promise.all([
        window.FleetAPI.getBitLockerStats().catch(() => ({})),
        window.FleetAPI.getBitLockerKeys({ query: _searchQuery }).catch(() => ({ keys: [] })),
        window.FleetAPI.getBitLockerPolicies().catch(() => ({ policies: [] })),
        window.FleetAPI.getBitLockerAuditLogs().catch(() => ({ audit_logs: [] })),
        window.FleetAPI.getGroups().catch(() => [])
      ]);

      _bitlockerStats = stats;
      _recoveryKeys = keysData.keys || [];
      _policies = policiesData.policies || [];
      _auditLogs = auditData.audit_logs || [];
      _groups = Array.isArray(groups) ? groups : (groups.groups || []);

      render(container);
    } catch (err) {
      container.innerHTML = `
        <div style="padding:32px;color:var(--ms-danger);">
          <h3>Failed to load BitLocker Recovery Vault</h3>
          <p>${esc(err.message)}</p>
          <button class="intune-btn" onclick="window.BitLockerTable.refresh()">Retry</button>
        </div>
      `;
    }
  }

  function render(container) {
    const stats = _bitlockerStats || {};
    const encRate = stats.encryption_rate_percent !== undefined ? stats.encryption_rate_percent : 100;
    const protectedVols = stats.protected_volumes || 0;
    const totalVols = stats.total_volumes || 0;
    const escrowedKeys = stats.total_escrowed_keys || 0;
    const auditCount = stats.total_audit_events || 0;

    container.innerHTML = `
      <div class="intune-blade-header" style="padding:24px 32px 16px;border-bottom:1px solid var(--ms-border);">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
          <div>
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
              <span style="font-size:24px;">🔑</span>
              <h1 style="font-size:22px;font-weight:600;margin:0;color:var(--ms-text-primary);">BitLocker Recovery Keys &amp; Drive Encryption</h1>
              <span class="intune-badge" style="background:#0F7B0F22;color:#0F7B0F;border:1px solid #0F7B0F44;font-size:11px;">Zero-Cloud Key Escrow</span>
            </div>
            <p style="margin:0;font-size:13px;color:var(--ms-text-secondary);">
              Enterprise recovery vault for 48-digit BitLocker passwords, hardware TPM protectors, silent drive encryption baselines, and tamper-evident access logs.
            </p>
          </div>
          <div style="display:flex;gap:8px;">
            <button class="intune-btn intune-btn-secondary" id="btn-refresh-bitlocker" title="Refresh Vault">
              🔄 Refresh
            </button>
            <button class="intune-btn intune-btn-primary" id="btn-create-bit-policy">
              + Create BitLocker Policy
            </button>
          </div>
        </div>

        <!-- KPI Strip -->
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:20px;">
          <!-- Card 1: Encryption Rate -->
          <div class="intune-card" style="padding:16px;background:var(--ms-bg-card);border:1px solid var(--ms-border);border-radius:6px;">
            <div style="font-size:11px;color:var(--ms-text-secondary);text-transform:uppercase;font-weight:600;letter-spacing:0.5px;">Fleet Encryption Rate</div>
            <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
              <span style="font-size:28px;font-weight:700;color:${encRate >= 80 ? '#0F7B0F' : '#D83B01'};">${encRate}%</span>
              <span style="font-size:12px;color:var(--ms-text-secondary);">${stats.encrypted_devices || 0} / ${stats.total_devices || 0} devices</span>
            </div>
            <div style="width:100%;height:4px;background:#e2e8f0;border-radius:2px;margin-top:10px;overflow:hidden;">
              <div style="width:${encRate}%;height:100%;background:${encRate >= 80 ? '#0F7B0F' : '#D83B01'};"></div>
            </div>
          </div>

          <!-- Card 2: Protected Volumes -->
          <div class="intune-card" style="padding:16px;background:var(--ms-bg-card);border:1px solid var(--ms-border);border-radius:6px;">
            <div style="font-size:11px;color:var(--ms-text-secondary);text-transform:uppercase;font-weight:600;letter-spacing:0.5px;">Protected Volumes</div>
            <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
              <span style="font-size:28px;font-weight:700;color:var(--ms-text-primary);">${protectedVols}</span>
              <span style="font-size:12px;color:var(--ms-text-secondary);">of ${totalVols} total volumes</span>
            </div>
            <div style="font-size:11px;color:var(--ms-text-secondary);margin-top:8px;">
              ${stats.unprotected_volumes || 0} volume(s) unprotected
            </div>
          </div>

          <!-- Card 3: Escrowed Keys -->
          <div class="intune-card" style="padding:16px;background:var(--ms-bg-card);border:1px solid var(--ms-border);border-radius:6px;">
            <div style="font-size:11px;color:var(--ms-text-secondary);text-transform:uppercase;font-weight:600;letter-spacing:0.5px;">Escrowed Recovery Keys</div>
            <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
              <span style="font-size:28px;font-weight:700;color:#0078D4;">${escrowedKeys}</span>
              <span style="font-size:12px;color:var(--ms-text-secondary);">in local vault</span>
            </div>
            <div style="font-size:11px;color:var(--ms-text-secondary);margin-top:8px;">
              🛡️ AES-256 / XTS Encrypted
            </div>
          </div>

          <!-- Card 4: Audit Logs -->
          <div class="intune-card" style="padding:16px;background:var(--ms-bg-card);border:1px solid var(--ms-border);border-radius:6px;">
            <div style="font-size:11px;color:var(--ms-text-secondary);text-transform:uppercase;font-weight:600;letter-spacing:0.5px;">Key Access Audit Events</div>
            <div style="display:flex;align-items:baseline;gap:8px;margin-top:6px;">
              <span style="font-size:28px;font-weight:700;color:${auditCount > 0 ? '#8B5CF6' : 'var(--ms-text-secondary)'};">${auditCount}</span>
              <span style="font-size:12px;color:var(--ms-text-secondary);">key reveals</span>
            </div>
            <div style="font-size:11px;color:var(--ms-text-secondary);margin-top:8px;">
              Immutable security paper trail
            </div>
          </div>
        </div>

        <!-- Sub-Tabs -->
        <div style="display:flex;gap:24px;margin-top:20px;border-bottom:1px solid var(--ms-border);">
          <button class="intune-subtab ${
            _activeSubTab === 'vault' ? 'active' : ''
          }" data-subtab="vault" style="padding:10px 4px;font-size:13px;font-weight:600;border:none;background:none;cursor:pointer;color:${
      _activeSubTab === 'vault' ? '#0078D4' : 'var(--ms-text-secondary)'
    };border-bottom:${_activeSubTab === 'vault' ? '2px solid #0078D4' : 'none'};">
            🔑 Recovery Key Vault (${_recoveryKeys.length})
          </button>
          <button class="intune-subtab ${
            _activeSubTab === 'policies' ? 'active' : ''
          }" data-subtab="policies" style="padding:10px 4px;font-size:13px;font-weight:600;border:none;background:none;cursor:pointer;color:${
      _activeSubTab === 'policies' ? '#0078D4' : 'var(--ms-text-secondary)'
    };border-bottom:${_activeSubTab === 'policies' ? '2px solid #0078D4' : 'none'};">
            📜 Disk Encryption Policies (${_policies.length})
          </button>
          <button class="intune-subtab ${
            _activeSubTab === 'audit' ? 'active' : ''
          }" data-subtab="audit" style="padding:10px 4px;font-size:13px;font-weight:600;border:none;background:none;cursor:pointer;color:${
      _activeSubTab === 'audit' ? '#0078D4' : 'var(--ms-text-secondary)'
    };border-bottom:${_activeSubTab === 'audit' ? '2px solid #0078D4' : 'none'};">
            ⚡ Key Access Audit Trail (${_auditLogs.length})
          </button>
        </div>
      </div>

      <!-- Tab Content Area -->
      <div style="padding:24px 32px;" id="bitlocker-subtab-content">
        ${renderSubTabContent()}
      </div>
    `;

    bindEvents(container);
  }

  function renderSubTabContent() {
    switch (_activeSubTab) {
      case 'vault':
        return renderRecoveryKeyVault();
      case 'policies':
        return renderBitLockerPolicies();
      case 'audit':
        return renderAuditLogs();
      default:
        return '';
    }
  }

  function renderRecoveryKeyVault() {
    return `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
        <div style="display:flex;gap:12px;align-items:center;flex:1;max-width:480px;">
          <input type="text" id="input-search-bitlocker-keys" class="intune-input"
            placeholder="Search by Key ID (e.g. E28B0F25), Device Hostname, or Drive..."
            value="${esc(_searchQuery)}"
            style="width:100%;font-size:13px;padding:8px 12px;" />
        </div>
        <div style="font-size:12px;color:var(--ms-text-secondary);">
          Showing ${_recoveryKeys.length} escrowed recovery key(s)
        </div>
      </div>

      <div class="intune-table-wrapper" style="background:var(--ms-bg-card);border:1px solid var(--ms-border);border-radius:6px;overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="background:var(--ms-bg-subtle);border-bottom:1px solid var(--ms-border);text-align:left;">
              <th style="padding:10px 14px;">Device / Hostname</th>
              <th style="padding:10px 14px;">Volume</th>
              <th style="padding:10px 14px;">Key ID (Short)</th>
              <th style="padding:10px 14px;">Recovery Password (Masked)</th>
              <th style="padding:10px 14px;">Cipher</th>
              <th style="padding:10px 14px;">Backed Up</th>
              <th style="padding:10px 14px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${
              _recoveryKeys.length === 0
                ? `<tr><td colspan="7" style="padding:32px;text-align:center;color:var(--ms-text-secondary);">No escrowed BitLocker keys found matching query.</td></tr>`
                : _recoveryKeys
                    .map(
                      k => `
              <tr style="border-bottom:1px solid var(--ms-border);">
                <td style="padding:12px 14px;">
                  <div style="font-weight:600;color:var(--ms-text-primary);">${esc(k.hostname)}</div>
                  <div style="font-size:11px;color:var(--ms-text-secondary);">${esc(k.primary_user || '—')}</div>
                </td>
                <td style="padding:12px 14px;">
                  <span style="font-weight:600;font-family:monospace;font-size:14px;background:#f1f5f9;padding:2px 6px;border-radius:4px;">
                    ${esc(k.volume_mount_point)}
                  </span>
                  <span style="font-size:11px;color:var(--ms-text-secondary);margin-left:4px;">(${esc(k.volume_type)})</span>
                </td>
                <td style="padding:12px 14px;">
                  <span style="font-family:monospace;font-weight:600;color:#0078D4;" title="${esc(k.key_protector_id)}">
                    ${esc(k.key_id_short || k.key_protector_id.slice(0, 8))}
                  </span>
                </td>
                <td style="padding:12px 14px;">
                  <div style="font-family:monospace;letter-spacing:1px;color:var(--ms-text-secondary);background:#f8fafc;padding:4px 8px;border-radius:4px;display:inline-block;border:1px solid #e2e8f0;">
                    ${esc(k.recovery_password_masked)}
                  </div>
                </td>
                <td style="padding:12px 14px;">
                  <span class="intune-badge" style="background:#e0f2fe;color:#0369a1;font-size:11px;">
                    ${esc(k.encryption_method || 'XtsAes128')}
                  </span>
                </td>
                <td style="padding:12px 14px;font-size:12px;color:var(--ms-text-secondary);">
                  ${esc(k.backup_timestamp ? k.backup_timestamp.replace('T', ' ').slice(0, 16) : '—')}
                  ${k.access_count > 0 ? `<div style="font-size:10px;color:#8B5CF6;font-weight:600;">Revealed ${k.access_count}x</div>` : ''}
                </td>
                <td style="padding:12px 14px;text-align:right;">
                  <button class="intune-btn intune-btn-secondary btn-reveal-key" data-id="${esc(k.id)}" data-dev="${esc(k.hostname)}" data-mount="${esc(k.volume_mount_point)}" style="padding:4px 10px;font-size:12px;">
                    👁️ Reveal
                  </button>
                  <button class="intune-btn intune-btn-secondary btn-rotate-key" data-dev-id="${esc(k.device_id)}" data-mount="${esc(k.volume_mount_point)}" style="padding:4px 8px;font-size:12px;margin-left:4px;" title="Rotate Key on Node">
                    🔄
                  </button>
                </td>
              </tr>
            `
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>
    `;
  }

  function renderBitLockerPolicies() {
    return `
      <div class="intune-table-wrapper" style="background:var(--ms-bg-card);border:1px solid var(--ms-border);border-radius:6px;overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="background:var(--ms-bg-subtle);border-bottom:1px solid var(--ms-border);text-align:left;">
              <th style="padding:10px 14px;">Policy Name</th>
              <th style="padding:10px 14px;">Target Group</th>
              <th style="padding:10px 14px;">OS Cipher</th>
              <th style="padding:10px 14px;">Fixed Cipher</th>
              <th style="padding:10px 14px;">TPM Protector</th>
              <th style="padding:10px 14px;">Key Rotation</th>
              <th style="padding:10px 14px;">Compliance</th>
              <th style="padding:10px 14px;text-align:right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${
              _policies.length === 0
                ? `<tr><td colspan="8" style="padding:32px;text-align:center;color:var(--ms-text-secondary);">No BitLocker policies configured.</td></tr>`
                : _policies
                    .map(
                      p => `
              <tr style="border-bottom:1px solid var(--ms-border);">
                <td style="padding:12px 14px;">
                  <div style="font-weight:600;color:var(--ms-text-primary);">${esc(p.name)}</div>
                  <div style="font-size:11px;color:var(--ms-text-secondary);max-width:320px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                    ${esc(p.description || '—')}
                  </div>
                </td>
                <td style="padding:12px 14px;">
                  <span class="intune-badge" style="background:${p.target_group_color || '#3B82F6'}22;color:${p.target_group_color || '#3B82F6'};">
                    ${esc(p.target_group_name || p.target_group_id)}
                  </span>
                </td>
                <td style="padding:12px 14px;">
                  <span style="font-family:monospace;font-size:12px;font-weight:600;">${esc(p.encryption_method_os)}</span>
                </td>
                <td style="padding:12px 14px;">
                  <span style="font-family:monospace;font-size:12px;font-weight:600;">${esc(p.encryption_method_fixed)}</span>
                </td>
                <td style="padding:12px 14px;">
                  <span class="intune-badge" style="${p.require_tpm ? 'background:#dcfce7;color:#15803d;' : 'background:#f1f5f9;color:#64748b;'}">
                    ${p.require_tpm ? '✓ Required' : 'Optional'}
                  </span>
                </td>
                <td style="padding:12px 14px;">
                  <span class="intune-badge" style="${p.recovery_key_rotation ? 'background:#dcfce7;color:#15803d;' : 'background:#f1f5f9;color:#64748b;'}">
                    ${p.recovery_key_rotation ? '✓ Enabled' : 'Disabled'}
                  </span>
                </td>
                <td style="padding:12px 14px;">
                  <div style="font-size:11px;font-weight:600;color:${p.encryption_rate_percent >= 80 ? '#0F7B0F' : '#D83B01'};">
                    ${p.encrypted_devices_count || 0} / ${p.targeted_devices_count || 0} (${p.encryption_rate_percent}%)
                  </div>
                  <div style="width:80px;height:4px;background:#e2e8f0;border-radius:2px;margin-top:4px;overflow:hidden;">
                    <div style="width:${p.encryption_rate_percent}%;height:100%;background:${p.encryption_rate_percent >= 80 ? '#0F7B0F' : '#D83B01'};"></div>
                  </div>
                </td>
                <td style="padding:12px 14px;text-align:right;">
                  <button class="intune-btn intune-btn-secondary btn-delete-bit-policy" data-id="${esc(p.id)}" style="padding:4px 8px;font-size:12px;color:var(--ms-danger);">
                    🗑️
                  </button>
                </td>
              </tr>
            `
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>
    `;
  }

  function renderAuditLogs() {
    return `
      <div style="margin-bottom:12px;font-size:12px;color:var(--ms-text-secondary);">
        BitLocker recovery password reveal paper trail. Every key lookup records operator identity, purpose, and IP.
      </div>
      <div class="intune-table-wrapper" style="background:var(--ms-bg-card);border:1px solid var(--ms-border);border-radius:6px;overflow:hidden;">
        <table class="intune-table" style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="background:var(--ms-bg-subtle);border-bottom:1px solid var(--ms-border);text-align:left;">
              <th style="padding:10px 14px;">Timestamp</th>
              <th style="padding:10px 14px;">Device / Hostname</th>
              <th style="padding:10px 14px;">Volume</th>
              <th style="padding:10px 14px;">Key ID</th>
              <th style="padding:10px 14px;">Accessed By</th>
              <th style="padding:10px 14px;">Access Reason</th>
              <th style="padding:10px 14px;">IP Address</th>
            </tr>
          </thead>
          <tbody>
            ${
              _auditLogs.length === 0
                ? `<tr><td colspan="7" style="padding:32px;text-align:center;color:var(--ms-text-secondary);">No key reveals logged yet.</td></tr>`
                : _auditLogs
                    .map(
                      a => `
              <tr style="border-bottom:1px solid var(--ms-border);">
                <td style="padding:12px 14px;font-size:12px;color:var(--ms-text-secondary);">
                  ${esc(a.accessed_at ? a.accessed_at.replace('T', ' ').slice(0, 19) : '—')}
                </td>
                <td style="padding:12px 14px;font-weight:600;color:var(--ms-text-primary);">
                  ${esc(a.hostname)}
                </td>
                <td style="padding:12px 14px;">
                  <span style="font-family:monospace;font-weight:600;">${esc(a.volume_mount_point)}</span>
                </td>
                <td style="padding:12px 14px;">
                  <span style="font-family:monospace;color:#0078D4;">${esc(a.key_protector_id ? a.key_protector_id.slice(0, 8) : '—')}</span>
                </td>
                <td style="padding:12px 14px;">
                  <span class="intune-badge" style="background:#f3e8ff;color:#7e22ce;font-weight:600;">
                    ${esc(a.accessed_by)}
                  </span>
                </td>
                <td style="padding:12px 14px;color:var(--ms-text-secondary);">
                  ${esc(a.access_reason || '—')}
                </td>
                <td style="padding:12px 14px;font-family:monospace;font-size:11px;color:var(--ms-text-secondary);">
                  ${esc(a.ip_address || '—')}
                </td>
              </tr>
            `
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>
    `;
  }

  function bindEvents(container) {
    // Refresh button
    container.querySelector('#btn-refresh-bitlocker')?.addEventListener('click', loadData);

    // Sub-tab switching
    container.querySelectorAll('.intune-subtab').forEach(btn => {
      btn.addEventListener('click', () => {
        _activeSubTab = btn.dataset.subtab;
        render(container);
      });
    });

    // Search input
    let searchTimeout = null;
    const searchInput = container.querySelector('#input-search-bitlocker-keys');
    searchInput?.addEventListener('input', e => {
      clearTimeout(searchTimeout);
      _searchQuery = e.target.value;
      searchTimeout = setTimeout(() => {
        window.FleetAPI.getBitLockerKeys({ query: _searchQuery }).then(res => {
          _recoveryKeys = res.keys || [];
          const content = container.querySelector('#bitlocker-subtab-content');
          if (content && _activeSubTab === 'vault') {
            content.innerHTML = renderRecoveryKeyVault();
            bindVaultActions(content);
          }
        });
      }, 250);
    });

    // Create policy button
    container.querySelector('#btn-create-bit-policy')?.addEventListener('click', openCreatePolicyModal);

    bindVaultActions(container);
  }

  function bindVaultActions(container) {
    // Reveal Key Button
    container.querySelectorAll('.btn-reveal-key').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.id;
        const devName = btn.dataset.dev;
        const mount = btn.dataset.mount;
        openRevealKeyModal(id, devName, mount);
      });
    });

    // Rotate Key Button
    container.querySelectorAll('.btn-rotate-key').forEach(btn => {
      btn.addEventListener('click', async () => {
        const devId = btn.dataset.devId;
        const mount = btn.dataset.mount;
        if (confirm(`Rotate BitLocker recovery key for drive ${mount} on this device? A new recovery password will be generated and uploaded to the vault.`)) {
          try {
            await window.FleetAPI.rotateDeviceBitLockerKey(devId, { mount_point: mount });
            alert(`Key rotation command dispatched to node. It will be executed on the next heartbeat.`);
          } catch (err) {
            alert(`Error dispatching key rotation: ${err.message}`);
          }
        }
      });
    });

    // Delete Policy Button
    container.querySelectorAll('.btn-delete-bit-policy').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        if (confirm(`Are you sure you want to delete this BitLocker policy?`)) {
          try {
            await window.FleetAPI.deleteBitLockerPolicy(id);
            loadData();
          } catch (err) {
            alert(`Error deleting policy: ${err.message}`);
          }
        }
      });
    });
  }

  function openRevealKeyModal(keyId, devName, mount) {
    const modalId = 'modal-reveal-bitlocker-key';
    let overlay = document.getElementById(modalId);
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = modalId;
      overlay.className = 'intune-modal-overlay';
      document.body.appendChild(overlay);
    }

    overlay.innerHTML = `
      <div class="intune-modal" style="max-width:560px;">
        <div class="intune-modal-header" style="background:#fef2f2;border-bottom:1px solid #fecaca;padding:16px 20px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:22px;">🔐</span>
            <h3 style="margin:0;font-size:16px;font-weight:600;color:#991b1b;">BitLocker Recovery Password Authorization</h3>
          </div>
          <button class="modal-close" style="background:none;border:none;font-size:18px;cursor:pointer;">&times;</button>
        </div>
        <div class="intune-modal-body" style="padding:20px;" id="reveal-modal-body">
          <div style="background:#fff1f2;border-left:4px solid #e11d48;padding:12px;border-radius:4px;font-size:12px;color:#9f1239;margin-bottom:16px;">
            <strong>Security Notice:</strong> You are about to view the unmasked 48-digit BitLocker recovery password for <strong>${esc(devName)} (${esc(mount)})</strong>. This action is permanently recorded in the immutable compliance audit log.
          </div>

          <div class="intune-form-group" style="margin-bottom:12px;">
            <label class="intune-label">Operator / Admin Name</label>
            <input type="text" id="reveal-operator" class="intune-input" value="Tony (Fleet Admin)" required style="width:100%;font-size:13px;" />
          </div>

          <div class="intune-form-group" style="margin-bottom:16px;">
            <label class="intune-label">Reason for Access / Ticket #</label>
            <input type="text" id="reveal-reason" class="intune-input" value="Endpoint rescue / BitLocker PIN recovery unlock" required style="width:100%;font-size:13px;" />
          </div>

          <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:20px;">
            <button class="intune-btn intune-btn-secondary" id="btn-cancel-reveal">Cancel</button>
            <button class="intune-btn intune-btn-primary" id="btn-confirm-reveal" style="background:#b91c1c;border-color:#b91c1c;">
              👁️ Authorize &amp; Reveal Key
            </button>
          </div>
        </div>
      </div>
    `;

    overlay.style.display = 'flex';

    overlay.querySelector('.modal-close').addEventListener('click', () => { overlay.style.display = 'none'; });
    overlay.querySelector('#btn-cancel-reveal').addEventListener('click', () => { overlay.style.display = 'none'; });

    overlay.querySelector('#btn-confirm-reveal').addEventListener('click', async () => {
      const operator = overlay.querySelector('#reveal-operator').value.trim() || 'Administrator';
      const reason = overlay.querySelector('#reveal-reason').value.trim() || 'BitLocker recovery';

      const bodyContainer = overlay.querySelector('#reveal-modal-body');
      bodyContainer.innerHTML = `<div style="text-align:center;padding:24px;">Authenticating and generating audit log...</div>`;

      try {
        const result = await window.FleetAPI.revealBitLockerKey(keyId, {
          accessed_by: operator,
          access_reason: reason
        });

        bodyContainer.innerHTML = `
          <div style="text-align:center;padding:12px 0;">
            <div style="font-size:12px;color:var(--ms-text-secondary);margin-bottom:6px;">48-DIGIT BITLOCKER RECOVERY PASSWORD</div>
            <div id="unmasked-bitlocker-pw" style="font-family:monospace;font-size:20px;font-weight:700;letter-spacing:1px;color:#1e293b;background:#f8fafc;padding:16px;border:2px dashed #0078D4;border-radius:6px;word-break:break-all;user-select:all;">
              ${esc(result.recovery_password)}
            </div>

            <div style="display:flex;justify-content:center;gap:12px;margin-top:16px;">
              <button class="intune-btn intune-btn-primary" id="btn-copy-bit-key" style="font-size:13px;padding:8px 18px;">
                📋 Copy 48-Digit Key
              </button>
              <button class="intune-btn intune-btn-secondary" id="btn-done-reveal" style="font-size:13px;">
                Done
              </button>
            </div>

            <div style="font-size:11px;color:#0F7B0F;margin-top:16px;">
              ✓ Access logged as Audit Event <strong>${esc(result.audit_record_id)}</strong>
            </div>
          </div>
        `;

        bodyContainer.querySelector('#btn-copy-bit-key').addEventListener('click', () => {
          navigator.clipboard.writeText(result.recovery_password);
          const btn = bodyContainer.querySelector('#btn-copy-bit-key');
          btn.textContent = '✓ Copied to Clipboard!';
          setTimeout(() => { btn.textContent = '📋 Copy 48-Digit Key'; }, 3000);
        });

        bodyContainer.querySelector('#btn-done-reveal').addEventListener('click', () => {
          overlay.style.display = 'none';
          loadData();
        });
      } catch (err) {
        bodyContainer.innerHTML = `
          <div style="color:var(--ms-danger);padding:16px;text-align:center;">
            Failed to reveal key: ${esc(err.message)}
          </div>
        `;
      }
    });
  }

  function openCreatePolicyModal() {
    const modalId = 'modal-create-bit-policy';
    let overlay = document.getElementById(modalId);
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = modalId;
      overlay.className = 'intune-modal-overlay';
      document.body.appendChild(overlay);
    }

    const groupOptions = _groups.map(g => `<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('');

    overlay.innerHTML = `
      <div class="intune-modal" style="max-width:620px;">
        <div class="intune-modal-header">
          <h3 style="margin:0;font-size:16px;">Create BitLocker Disk Encryption Policy</h3>
          <button class="modal-close" style="background:none;border:none;font-size:18px;cursor:pointer;">&times;</button>
        </div>
        <div class="intune-modal-body" style="padding:20px;">
          <!-- Presets -->
          <div style="margin-bottom:16px;">
            <label class="intune-label">Quick Presets</label>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button type="button" class="intune-btn intune-btn-secondary btn-preset-bit" data-preset="enterprise" style="font-size:11px;">
                🛡️ Enterprise Silent Baseline
              </button>
              <button type="button" class="intune-btn intune-btn-secondary btn-preset-bit" data-preset="high-sec" style="font-size:11px;">
                🔒 Military Grade (XTS-256)
              </button>
              <button type="button" class="intune-btn intune-btn-secondary btn-preset-bit" data-preset="laptop" style="font-size:11px;">
                💼 Family Laptop Standard
              </button>
            </div>
          </div>

          <form id="form-create-bit-policy">
            <div class="intune-form-group" style="margin-bottom:12px;">
              <label class="intune-label">Policy Name *</label>
              <input type="text" id="bit-pol-name" class="intune-input" required placeholder="e.g. Windows 11 Silent BitLocker Baseline" style="width:100%;" />
            </div>

            <div class="intune-form-group" style="margin-bottom:12px;">
              <label class="intune-label">Description</label>
              <textarea id="bit-pol-desc" class="intune-input" rows="2" style="width:100%;font-size:12px;" placeholder="Policy scope and hardware encryption objectives..."></textarea>
            </div>

            <div class="intune-form-group" style="margin-bottom:12px;">
              <label class="intune-label">Target Dynamic Group</label>
              <select id="bit-pol-target" class="intune-select" style="width:100%;">
                <option value="grp-all">All Devices (grp-all)</option>
                ${groupOptions}
              </select>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
              <div class="intune-form-group">
                <label class="intune-label">Operating System Drive Cipher</label>
                <select id="bit-pol-cipher-os" class="intune-select" style="width:100%;">
                  <option value="XtsAes128" selected>XTS-AES 128-bit (Standard)</option>
                  <option value="XtsAes256">XTS-AES 256-bit (High Assurance)</option>
                  <option value="Aes128">AES-CBC 128-bit (Legacy)</option>
                  <option value="Aes256">AES-CBC 256-bit (Legacy)</option>
                </select>
              </div>

              <div class="intune-form-group">
                <label class="intune-label">Fixed Data Drive Cipher</label>
                <select id="bit-pol-cipher-fixed" class="intune-select" style="width:100%;">
                  <option value="XtsAes128" selected>XTS-AES 128-bit (Standard)</option>
                  <option value="XtsAes256">XTS-AES 256-bit (High Assurance)</option>
                  <option value="Aes128">AES-CBC 128-bit (Legacy)</option>
                  <option value="Aes256">AES-CBC 256-bit (Legacy)</option>
                </select>
              </div>
            </div>

            <div style="margin-bottom:16px;">
              <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:6px;">
                <input type="checkbox" id="bit-pol-tpm" checked />
                <span>Require Hardware TPM (TPM 2.0 Security Chip)</span>
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:6px;">
                <input type="checkbox" id="bit-pol-rotation" checked />
                <span>Enable Automated Recovery Key Rotation</span>
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:6px;">
                <input type="checkbox" id="bit-pol-silent" checked />
                <span>Enable Silent Device Encryption (Zero User Prompts)</span>
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
                <input type="checkbox" id="bit-pol-hide-opts" checked />
                <span>Hide BitLocker Setup Wizard Recovery Options from End-Users</span>
              </label>
            </div>

            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:20px;">
              <button type="button" class="intune-btn intune-btn-secondary btn-cancel-modal">Cancel</button>
              <button type="submit" class="intune-btn intune-btn-primary">Save Policy</button>
            </div>
          </form>
        </div>
      </div>
    `;

    overlay.style.display = 'flex';

    overlay.querySelector('.modal-close').addEventListener('click', () => { overlay.style.display = 'none'; });
    overlay.querySelector('.btn-cancel-modal').addEventListener('click', () => { overlay.style.display = 'none'; });

    // Preset handlers
    overlay.querySelectorAll('.btn-preset-bit').forEach(btn => {
      btn.addEventListener('click', () => {
        const type = btn.dataset.preset;
        if (type === 'enterprise') {
          overlay.querySelector('#bit-pol-name').value = 'Enterprise Silent BitLocker Baseline';
          overlay.querySelector('#bit-pol-desc').value = 'Silent XTS-AES 128-bit hardware encryption for all Windows drives.';
          overlay.querySelector('#bit-pol-cipher-os').value = 'XtsAes128';
          overlay.querySelector('#bit-pol-cipher-fixed').value = 'XtsAes128';
          overlay.querySelector('#bit-pol-tpm').checked = true;
          overlay.querySelector('#bit-pol-rotation').checked = true;
          overlay.querySelector('#bit-pol-silent').checked = true;
        } else if (type === 'high-sec') {
          overlay.querySelector('#bit-pol-name').value = 'Military Grade High-Assurance BitLocker';
          overlay.querySelector('#bit-pol-desc').value = 'Maximum security configuration requiring XTS-AES 256-bit encryption cipher.';
          overlay.querySelector('#bit-pol-cipher-os').value = 'XtsAes256';
          overlay.querySelector('#bit-pol-cipher-fixed').value = 'XtsAes256';
          overlay.querySelector('#bit-pol-tpm').checked = true;
          overlay.querySelector('#bit-pol-rotation').checked = true;
          overlay.querySelector('#bit-pol-silent').checked = true;
        } else if (type === 'laptop') {
          overlay.querySelector('#bit-pol-name').value = 'Family Laptop BitLocker Standard';
          overlay.querySelector('#bit-pol-desc').value = 'Standard XTS-AES 128-bit encryption for portable family laptops.';
          overlay.querySelector('#bit-pol-cipher-os').value = 'XtsAes128';
          overlay.querySelector('#bit-pol-cipher-fixed').value = 'XtsAes128';
          overlay.querySelector('#bit-pol-tpm').checked = true;
          overlay.querySelector('#bit-pol-rotation').checked = true;
          overlay.querySelector('#bit-pol-silent').checked = true;
        }
      });
    });

    // Form submission
    overlay.querySelector('#form-create-bit-policy').addEventListener('submit', async e => {
      e.preventDefault();
      const payload = {
        name: overlay.querySelector('#bit-pol-name').value.trim(),
        description: overlay.querySelector('#bit-pol-desc').value.trim(),
        target_group_id: overlay.querySelector('#bit-pol-target').value,
        encryption_method_os: overlay.querySelector('#bit-pol-cipher-os').value,
        encryption_method_fixed: overlay.querySelector('#bit-pol-cipher-fixed').value,
        require_tpm: overlay.querySelector('#bit-pol-tpm').checked,
        recovery_key_rotation: overlay.querySelector('#bit-pol-rotation').checked,
        silent_encryption_enabled: overlay.querySelector('#bit-pol-silent').checked,
        hide_recovery_options_in_wizard: overlay.querySelector('#bit-pol-hide-opts').checked
      };

      try {
        await window.FleetAPI.createBitLockerPolicy(payload);
        overlay.style.display = 'none';
        loadData();
      } catch (err) {
        alert(`Error saving policy: ${err.message}`);
      }
    });
  }

  // Export
  window.BitLockerTable = {
    init: loadData,
    refresh: loadData
  };
})();
