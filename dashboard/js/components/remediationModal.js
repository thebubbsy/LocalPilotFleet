/**
 * LocalPilot Fleet — Proactive Remediation Create / Edit Modal
 * dashboard/js/components/remediationModal.js
 */

(function () {
  let _onSaveCallback = null;

  const TEMPLATES = {
    custom: {
      name: '',
      description: '',
      det: `# Detection script - Exit 0 for Healthy, Exit 1 for Issue Detected\n$status = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue\nif ($status.Status -ne 'Running') {\n  Write-Host "Issue detected"\n  exit 1\n}\nWrite-Host "Healthy"\nexit 0`,
      rem: `# Remediation script - Runs only if Detection exits 1\nStart-Service -Name "Spooler"\nWrite-Host "Remediated"\nexit 0`
    },
    temp_cleaner: {
      name: 'Purge Stale Temp Files & Crash Dumps',
      description: 'Detects if temporary folders exceed 500 MB of stale files and safely deletes items older than 24 hours.',
      det: `$tempPaths = @($env:TEMP, 'C:\\Windows\\Temp')\n$totalBytes = 0\nforeach ($p in $tempPaths) {\n  if (Test-Path $p) {\n    $files = Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) }\n    $totalBytes += ($files | Measure-Object -Property Length -Sum).Sum\n  }\n}\n$totalMb = [math]::Round($totalBytes / 1MB, 1)\nif ($totalMb -gt 500) {\n  Write-Host "Stale temporary files detected: $totalMb MB (threshold: 500 MB)"\n  exit 1\n}\nWrite-Host "Temp storage healthy: $totalMb MB stale files (threshold: 500 MB)"\nexit 0`,
      rem: `$tempPaths = @($env:TEMP, 'C:\\Windows\\Temp')\n$freedBytes = 0\nforeach ($p in $tempPaths) {\n  if (Test-Path $p) {\n    $files = Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) }\n    foreach ($f in $files) {\n      try {\n        $len = $f.Length\n        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop\n        $freedBytes += $len\n      } catch {}\n    }\n  }\n}\n$freedMb = [math]::Round($freedBytes / 1MB, 1)\nWrite-Host "Purged $freedMb MB of stale temporary files."\nexit 0`
    },
    spooler: {
      name: 'Self-Healing Print Spooler Service',
      description: 'Monitors the Windows Print Spooler; restarts service and corrects startup config if stopped.',
      det: `$svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue\nif (-not $svc) { Write-Host "Print Spooler service not found"; exit 0 }\nif ($svc.Status -ne 'Running') {\n  Write-Host "Print Spooler is stopped (Current status: $($svc.Status))"\n  exit 1\n}\nWrite-Host "Print Spooler service is running normally"\nexit 0`,
      rem: `Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue\nStart-Service -Name Spooler -ErrorAction Stop\nWrite-Host "Print Spooler service restarted and set to Automatic startup."\nexit 0`
    },
    dns: {
      name: 'DNS Client Cache Flush & Adapter Self-Heal',
      description: 'Validates local DNS resolution and automatically purges stale DNS cache entries.',
      det: `$dnsTest = Resolve-DnsName -Name "localhost" -ErrorAction SilentlyContinue\nif (-not $dnsTest) {\n  Write-Host "DNS client cache failed resolution test"\n  exit 1\n}\nWrite-Host "DNS resolution operational"\nexit 0`,
      rem: `Clear-DnsClientCache\nWrite-Host "Flushed Windows DNS Client Cache successfully."\nexit 0`
    }
  };

  function esc(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  async function open(packageId = null, onSave = null) {
    _onSaveCallback = onSave;
    let pkg = null;
    let groups = [];

    try {
      const gRes = await window.FleetAPI.getGroups();
      groups = gRes.groups || [];
    } catch (err) {}

    if (packageId) {
      try {
        pkg = await window.FleetAPI.getRemediationDetails(packageId);
      } catch (err) {}
    }

    renderModal(pkg, groups);
  }

  function close() {
    const modal = document.getElementById('rem-create-modal');
    if (modal) modal.remove();
  }

  function renderModal(pkg, groups) {
    close();

    const isEdit = Boolean(pkg);
    const modal = document.createElement('div');
    modal.id = 'rem-create-modal';
    modal.className = 'modal-overlay';
    modal.style.display = 'flex';

    modal.innerHTML = `
      <div class="modal-dialog" style="max-width: 800px; width: 95%; max-height: 90vh; display: flex; flex-direction: column;">
        <div class="modal-header" style="padding: 16px 20px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
          <h3 style="margin: 0; font-size: 17px; color: var(--text-primary);">
            ${isEdit ? '✎ Edit Remediation Script Package' : '+ Create Script Package'}
          </h3>
          <button class="btn-close" id="btn-close-create" style="background: none; border: none; font-size: 20px; cursor: pointer; color: var(--text-muted);">&times;</button>
        </div>

        <form id="rem-form" style="display: flex; flex-direction: column; flex: 1; overflow-y: auto;">
          <div class="modal-body" style="padding: 20px; flex: 1;">
            
            ${!isEdit ? `
              <div style="margin-bottom: 16px; background: var(--bg-hover); padding: 12px; border-radius: 6px;">
                <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px;">
                  Quick Start Template:
                </label>
                <select id="rem-template-picker" class="form-control" style="width: 100%;">
                  <option value="custom">-- Custom Script Package --</option>
                  <option value="temp_cleaner">Auto-Clean Stale Temporary Files & Crash Dumps</option>
                  <option value="spooler">Self-Healing Print Spooler Service</option>
                  <option value="dns">DNS Client Cache Flush & Adapter Self-Heal</option>
                </select>
              </div>
            ` : ''}

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 14px;">
              <div>
                <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">Package Name *</label>
                <input type="text" id="rem-name" class="form-control" style="width: 100%;" required placeholder="e.g. Stale Temp Cleaner" value="${esc(pkg?.name || '')}" />
              </div>
              <div>
                <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">Target Device Group</label>
                <select id="rem-target-group" class="form-control" style="width: 100%;">
                  <option value="grp-all" ${pkg?.target_group_id === 'grp-all' ? 'selected' : ''}>All Devices (grp-all)</option>
                  ${groups.map(g => `
                    <option value="${esc(g.id)}" ${pkg?.target_group_id === g.id ? 'selected' : ''}>${esc(g.name)} (${esc(g.id)})</option>
                  `).join('')}
                </select>
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 14px;">
              <div>
                <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">Schedule</label>
                <select id="rem-schedule" class="form-control" style="width: 100%;">
                  <option value="HEARTBEAT" ${pkg?.schedule_type === 'HEARTBEAT' ? 'selected' : ''}>Every Heartbeat (~5m / fast)</option>
                  <option value="HOURLY" ${pkg?.schedule_type === 'HOURLY' ? 'selected' : ''}>Hourly</option>
                  <option value="DAILY" ${pkg?.schedule_type === 'DAILY' ? 'selected' : ''}>Daily</option>
                </select>
              </div>
              <div>
                <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">Publisher</label>
                <input type="text" id="rem-pub" class="form-control" style="width: 100%;" value="${esc(pkg?.publisher || 'LocalPilot Admin')}" />
              </div>
            </div>

            <div style="margin-bottom: 14px;">
              <label style="display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">Description</label>
              <textarea id="rem-desc" class="form-control" rows="2" style="width: 100%;" placeholder="Describe the problem this package detects and remedies…">${esc(pkg?.description || '')}</textarea>
            </div>

            <div style="margin-bottom: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary);">
                  🔍 Detection Script (PowerShell) *
                </label>
                <span style="font-size: 11px; color: var(--text-muted);">Exit 0 = Healthy | Exit 1 = Non-compliant</span>
              </div>
              <textarea id="rem-det-script" class="form-control" rows="6" style="width: 100%; font-family: monospace; font-size: 12px;" required>${esc(pkg?.detection_script || TEMPLATES.custom.det)}</textarea>
            </div>

            <div style="margin-bottom: 14px;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary);">
                  🩺 Remediation Script (PowerShell) *
                </label>
                <span style="font-size: 11px; color: var(--text-muted);">Runs only if detection exits 1 | Exit 0 = Resolved</span>
              </div>
              <textarea id="rem-fix-script" class="form-control" rows="6" style="width: 100%; font-family: monospace; font-size: 12px;" required>${esc(pkg?.remediation_script || TEMPLATES.custom.rem)}</textarea>
            </div>

          </div>

          <div class="modal-footer" style="padding: 14px 20px; border-top: 1px solid var(--border-color); display: flex; justify-content: flex-end; gap: 10px;">
            <button type="button" class="btn btn-secondary" id="btn-cancel-create">Cancel</button>
            <button type="submit" class="btn btn-primary" id="btn-submit-create">
              ${isEdit ? 'Save Changes' : 'Create Script Package'}
            </button>
          </div>
        </form>
      </div>
    `;

    document.body.appendChild(modal);
    bindEvents(modal, pkg);
  }

  function bindEvents(modal, pkg) {
    modal.querySelector('#btn-close-create')?.addEventListener('click', close);
    modal.querySelector('#btn-cancel-create')?.addEventListener('click', close);
    modal.addEventListener('click', (e) => {
      if (e.target === modal) close();
    });

    // Template Picker
    const tplPicker = modal.querySelector('#rem-template-picker');
    tplPicker?.addEventListener('change', () => {
      const selected = TEMPLATES[tplPicker.value];
      if (selected) {
        if (selected.name) modal.querySelector('#rem-name').value = selected.name;
        if (selected.description) modal.querySelector('#rem-desc').value = selected.description;
        modal.querySelector('#rem-det-script').value = selected.det;
        modal.querySelector('#rem-fix-script').value = selected.rem;
      }
    });

    // Submit handler
    const form = modal.querySelector('#rem-form');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();

      const payload = {
        name: modal.querySelector('#rem-name').value.trim(),
        target_group_id: modal.querySelector('#rem-target-group').value,
        schedule_type: modal.querySelector('#rem-schedule').value,
        publisher: modal.querySelector('#rem-pub').value.trim(),
        description: modal.querySelector('#rem-desc').value.trim(),
        detection_script: modal.querySelector('#rem-det-script').value.trim(),
        remediation_script: modal.querySelector('#rem-fix-script').value.trim()
      };

      const btnSubmit = modal.querySelector('#btn-submit-create');
      btnSubmit.disabled = true;
      btnSubmit.textContent = 'Saving…';

      try {
        if (pkg?.id) {
          await window.FleetAPI.updateRemediation(pkg.id, payload);
          if (typeof showToast === 'function') showToast('Package Updated', `Saved "${payload.name}"`, 'success');
        } else {
          await window.FleetAPI.createRemediation(payload);
          if (typeof showToast === 'function') showToast('Package Created', `Created "${payload.name}"`, 'success');
        }

        close();
        if (_onSaveCallback) _onSaveCallback();
      } catch (err) {
        if (typeof showToast === 'function') showToast('Save Failed', err.message, 'critical');
        btnSubmit.disabled = false;
        btnSubmit.textContent = pkg?.id ? 'Save Changes' : 'Create Script Package';
      }
    });
  }

  window.RemediationModal = {
    open,
    close
  };
})();
