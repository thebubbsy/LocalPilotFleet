/**
 * LocalPilot Fleet — Interactive Cloud Shell / Remote Terminal
 * dashboard/js/components/remoteTerminal.js
 *
 * Provides a Microsoft Intune / Azure Cloud Shell drawer to execute live PowerShell
 * commands across enrolled fleet nodes directly from the web portal.
 */

(function () {
  'use strict';

  let _activeDeviceId = null;
  let _history = [];
  let _historyIdx = -1;
  let _activePollInterval = null;

  const SNIPPETS = [
    { label: '⚡ Top CPU Procs', cmd: 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 -Property Id, ProcessName, @{N="CPU(s)";E={[math]::Round($_.CPU,2)}}, @{N="RAM(MB)";E={[math]::Round($_.WorkingSet/1MB,1)}} | Format-Table -AutoSize' },
    { label: '⚡ Running Services', cmd: 'Get-Service | Where-Object Status -eq "Running" | Select-Object -First 15 -Property Name, DisplayName, Status | Format-Table -AutoSize' },
    { label: '⚡ gpupdate /force', cmd: 'gpupdate /force' },
    { label: '⚡ winget list', cmd: 'winget list --accept-source-agreements | Select-Object -First 25' },
    { label: '⚡ IP Config', cmd: 'Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize' },
    { label: '⚡ Recent Hotfixes', cmd: 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 -Property HotFixID, Description, InstalledOn | Format-Table -AutoSize' },
    { label: '⚡ Flush DNS', cmd: 'Clear-DnsClientCache; Write-Host "DNS cache flushed successfully."' },
    { label: '⚡ Active Logged-in User', cmd: '(Get-CimInstance Win32_ComputerSystem).UserName; query user 2>$null' }
  ];

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function appendOutput(html) {
    const out = document.getElementById('cloud-shell-output');
    if (!out) return;
    out.innerHTML += html;
    out.scrollTop = out.scrollHeight;
  }

  function setStatus(text, type = 'ready') {
    const badge = document.getElementById('cloud-shell-status-badge');
    if (!badge) return;
    badge.textContent = text;
    badge.className = `shell-status-pill status-${type}`;
  }

  async function populateDevicePicker(selectedId) {
    const sel = document.getElementById('cloud-shell-device-select');
    if (!sel) return;

    try {
      const data = await window.FleetAPI.getDevices();
      const devices = data.devices || [];
      sel.innerHTML = devices.map(d => {
        const user = d.primary_user ? ` (${d.primary_user})` : '';
        const isSelected = (d.id === selectedId || (!selectedId && d.status === 'online')) ? 'selected' : '';
        return `<option value="${esc(d.id)}" ${isSelected}>${esc(d.hostname)}${esc(user)} [${esc(d.status)}]</option>`;
      }).join('');

      if (!selectedId && sel.value) {
        _activeDeviceId = sel.value;
      } else {
        _activeDeviceId = selectedId || sel.value;
      }
    } catch (err) {
      sel.innerHTML = `<option value="">Failed to load devices</option>`;
    }
  }

  function open(deviceId = null) {
    const drawer = document.getElementById('cloud-shell-drawer');
    const overlay = document.getElementById('cloud-shell-overlay');
    if (!drawer) return;

    drawer.classList.add('open');
    if (overlay) overlay.classList.add('open');

    populateDevicePicker(deviceId);

    const input = document.getElementById('cloud-shell-input');
    if (input) {
      setTimeout(() => input.focus(), 150);
    }
  }

  function close() {
    const drawer = document.getElementById('cloud-shell-drawer');
    const overlay = document.getElementById('cloud-shell-overlay');
    if (drawer) drawer.classList.remove('open');
    if (overlay) overlay.classList.remove('open');
    if (_activePollInterval) {
      clearInterval(_activePollInterval);
      _activePollInterval = null;
    }
  }

  function clearOutput() {
    const out = document.getElementById('cloud-shell-output');
    if (out) {
      out.innerHTML = `
        <div class="shell-line shell-system">LocalPilot Fleet Cloud Shell [Version 1.0.0]</div>
        <div class="shell-line shell-system">Connected to Master Authority. Select a device and run PowerShell commands.</div>
        <div class="shell-line shell-system">───────────────────────────────────────────────────────────────────────</div>
      `;
    }
  }

  async function executeScript(scriptText) {
    const trimmed = (scriptText || '').trim();
    if (!trimmed) return;

    const sel = document.getElementById('cloud-shell-device-select');
    const targetId = sel?.value || _activeDeviceId;
    const targetName = sel?.options[sel.selectedIndex]?.text || targetId;

    if (!targetId) {
      appendOutput(`<div class="shell-line shell-error">❌ No target device selected in the fleet.</div>`);
      return;
    }

    _history.push(trimmed);
    _historyIdx = _history.length;

    const timeStr = new Date().toLocaleTimeString();
    appendOutput(`
      <div class="shell-cmd-block">
        <div class="shell-line shell-prompt-line">
          <span class="shell-prompt">PS [${esc(targetName.split(' ')[0])}]&gt;</span>
          <span class="shell-cmd-text">${esc(trimmed)}</span>
          <span class="shell-timestamp">${esc(timeStr)}</span>
        </div>
        <div class="shell-line shell-info" id="status-line-${Date.now()}">
          ⏳ Queuing command on Fleet Authority...
        </div>
      </div>
    `);

    setStatus('Queued', 'queued');

    try {
      const res = await window.FleetAPI.runScript(targetId, trimmed);
      const commandId = res.command_id;

      appendOutput(`
        <div class="shell-line shell-info">
          📡 Command queued (ID: <code>${esc(commandId.slice(0, 8))}</code>). Waiting for node agent execution...
        </div>
      `);

      setStatus('Running on node', 'running');

      // Poll command result
      let attempts = 0;
      const maxAttempts = 40; // 60s max

      if (_activePollInterval) clearInterval(_activePollInterval);

      _activePollInterval = setInterval(async () => {
        attempts++;
        try {
          const cmd = await window.FleetAPI.getCommandStatus(commandId);
          if (cmd.status === 'COMPLETED' || cmd.status === 'FAILED') {
            clearInterval(_activePollInterval);
            _activePollInterval = null;

            const isSuccess = cmd.status === 'COMPLETED' && (cmd.exit_code === 0 || cmd.exit_code === null);
            setStatus(isSuccess ? 'Completed' : 'Failed', isSuccess ? 'success' : 'error');

            let outHtml = '';
            if (cmd.stdout && cmd.stdout.trim()) {
              outHtml += `<pre class="shell-stdout">${esc(cmd.stdout)}</pre>`;
            }
            if (cmd.stderr && cmd.stderr.trim()) {
              outHtml += `<pre class="shell-stderr">${esc(cmd.stderr)}</pre>`;
            }
            if (!cmd.stdout && !cmd.stderr) {
              outHtml += `<div class="shell-line shell-system">[Command executed with no output returned]</div>`;
            }

            const badgeCls = isSuccess ? 'badge-online' : 'badge-quarantined';
            outHtml += `
              <div class="shell-line shell-summary">
                <span class="badge ${badgeCls}">Exit code: ${cmd.exit_code ?? 0}</span>
                <span style="margin-left:8px;color:#888;">Completed at ${new Date(cmd.completed_at || Date.now()).toLocaleTimeString()}</span>
              </div>
            `;

            appendOutput(outHtml);
          } else if (attempts >= maxAttempts) {
            clearInterval(_activePollInterval);
            _activePollInterval = null;
            setStatus('Timed out', 'error');
            appendOutput(`
              <div class="shell-line shell-error">
                ⚠️ Execution wait timed out after 60 seconds. The command remains queued on the node and will execute on next heartbeat.
              </div>
            `);
          }
        } catch (err) {
          // keep polling or log
        }
      }, 1500);

    } catch (err) {
      setStatus('Dispatch failed', 'error');
      appendOutput(`<div class="shell-line shell-error">❌ Dispatch error: ${esc(err.message)}</div>`);
    }
  }

  function init() {
    // Render drawer HTML into DOM if not present
    if (!document.getElementById('cloud-shell-drawer')) {
      const drawerDiv = document.createElement('div');
      drawerDiv.id = 'cloud-shell-drawer';
      drawerDiv.className = 'cloud-shell-container';
      drawerDiv.innerHTML = `
        <div class="shell-header-bar">
          <div class="shell-header-left">
            <span class="shell-header-icon">&gt;_</span>
            <span class="shell-header-title">Cloud Shell</span>
            <span class="shell-env-tag">PowerShell</span>
            <div class="shell-target-picker">
              <label for="cloud-shell-device-select">Target:</label>
              <select id="cloud-shell-device-select" class="shell-select"></select>
            </div>
            <span id="cloud-shell-status-badge" class="shell-status-pill status-ready">Ready</span>
          </div>
          <div class="shell-header-right">
            <button class="shell-btn-icon" id="btn-shell-clear" title="Clear console">🧹 Clear</button>
            <button class="shell-btn-icon" id="btn-shell-toggle-size" title="Expand / Shrink">⛶</button>
            <button class="shell-btn-icon" id="btn-shell-close" title="Close Cloud Shell">&times;</button>
          </div>
        </div>

        <!-- Quick Action Snippets -->
        <div class="shell-snippets-bar">
          <span class="snippet-label">Quick actions:</span>
          ${SNIPPETS.map((s, idx) => `
            <button class="shell-snippet-btn" data-snippet-idx="${idx}" title="${esc(s.cmd)}">${esc(s.label)}</button>
          `).join('')}
        </div>

        <!-- Terminal Output Screen -->
        <div class="shell-terminal-screen" id="cloud-shell-output">
          <div class="shell-line shell-system">LocalPilot Fleet Cloud Shell [Version 1.0.0]</div>
          <div class="shell-line shell-system">Zero-cloud Microsoft Intune management &amp; remote PowerShell executor.</div>
          <div class="shell-line shell-system">───────────────────────────────────────────────────────────────────────</div>
        </div>

        <!-- Interactive Input Line -->
        <div class="shell-input-wrapper">
          <span class="shell-input-prompt">PS &gt;</span>
          <input type="text" id="cloud-shell-input" class="shell-input" placeholder="Type PowerShell command (e.g. Get-Process, gpupdate /force)..." autocomplete="off" spellcheck="false">
          <button id="cloud-shell-send-btn" class="shell-run-btn">Run</button>
        </div>
      `;
      document.body.appendChild(drawerDiv);

      const overlayDiv = document.createElement('div');
      overlayDiv.id = 'cloud-shell-overlay';
      overlayDiv.className = 'cloud-shell-overlay';
      document.body.appendChild(overlayDiv);
    }

    // Attach event listeners
    const input = document.getElementById('cloud-shell-input');
    const sendBtn = document.getElementById('cloud-shell-send-btn');
    const closeBtn = document.getElementById('btn-shell-close');
    const clearBtn = document.getElementById('btn-shell-clear');
    const expandBtn = document.getElementById('btn-shell-toggle-size');
    const overlay = document.getElementById('cloud-shell-overlay');

    sendBtn?.addEventListener('click', () => {
      const cmd = input?.value;
      if (cmd) {
        input.value = '';
        executeScript(cmd);
      }
    });

    input?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const cmd = input.value;
        if (cmd) {
          input.value = '';
          executeScript(cmd);
        }
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (_history.length > 0 && _historyIdx > 0) {
          _historyIdx--;
          input.value = _history[_historyIdx];
        }
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (_historyIdx < _history.length - 1) {
          _historyIdx++;
          input.value = _history[_historyIdx];
        } else {
          _historyIdx = _history.length;
          input.value = '';
        }
      }
    });

    closeBtn?.addEventListener('click', close);
    overlay?.addEventListener('click', close);
    clearBtn?.addEventListener('click', clearOutput);

    expandBtn?.addEventListener('click', () => {
      const drawer = document.getElementById('cloud-shell-drawer');
      drawer?.classList.toggle('maximized');
    });

    // Snippet button clicks
    document.querySelectorAll('.shell-snippet-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-snippet-idx'), 10);
        const snippet = SNIPPETS[idx];
        if (snippet && input) {
          input.value = snippet.cmd;
          input.focus();
        }
      });
    });

    // Top header Cloud Shell button
    const topBarBtn = document.getElementById('btn-terminal') || document.querySelector('button[title*="Cloud Shell"]');
    if (topBarBtn) {
      topBarBtn.id = 'btn-terminal';
      topBarBtn.addEventListener('click', () => open());
    }

    // Listen to SSE command completed events
    document.addEventListener('fleet:event', (e) => {
      const d = e.detail;
      if (d && d.event_type === 'command_completed') {
        appendOutput(`
          <div class="shell-line shell-info">
            🔔 SSE Update: Command completed on device.
          </div>
        `);
      }
    });
  }

  // Self-init on DOMContentLoaded or immediate if already loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.RemoteTerminal = {
    open,
    close,
    execute: executeScript,
    clear: clearOutput
  };
})();
