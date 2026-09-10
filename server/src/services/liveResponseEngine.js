/**
 * LocalPilot Fleet — Endpoint Remediation Automation & Custom Live Response Service Engine
 * server/src/services/liveResponseEngine.js
 *
 * Implements Microsoft Defender for Endpoint & CrowdStrike Falcon equivalent live response
 * interactive terminal command queues, custom detection & remediation playbooks,
 * file quarantine vault management, and remote incident response telemetry.
 */

import crypto from 'node:crypto';

export class LiveResponseEngine {
  /**
   * Aggregate fleet-wide live response, remediation, and quarantine statistics
   */
  static getLiveResponseStats(db) {
    const totalPackages = db.prepare('SELECT COUNT(*) as count FROM custom_remediation_packages').get()?.count || 0;
    const activePackages = db.prepare('SELECT COUNT(*) as count FROM custom_remediation_packages WHERE is_active = 1').get()?.count || 0;

    const totalSessions = db.prepare('SELECT COUNT(DISTINCT session_id) as count FROM live_response_command_sessions').get()?.count || 0;
    const activeSessions = db.prepare("SELECT COUNT(DISTINCT session_id) as count FROM live_response_command_sessions WHERE status IN ('QUEUED', 'IN_PROGRESS')").get()?.count || 0;

    const totalCommands = db.prepare('SELECT COUNT(*) as count FROM live_response_command_sessions').get()?.count || 0;
    const queuedCommands = db.prepare("SELECT COUNT(*) as count FROM live_response_command_sessions WHERE status = 'QUEUED'").get()?.count || 0;
    const completedCommands = db.prepare("SELECT COUNT(*) as count FROM live_response_command_sessions WHERE status = 'COMPLETED'").get()?.count || 0;
    const failedCommands = db.prepare("SELECT COUNT(*) as count FROM live_response_command_sessions WHERE status = 'FAILED'").get()?.count || 0;

    const quarantinedFiles = db.prepare("SELECT COUNT(*) as count FROM quarantined_files_inventory WHERE status = 'QUARANTINED'").get()?.count || 0;
    const restoredFiles = db.prepare("SELECT COUNT(*) as count FROM quarantined_files_inventory WHERE status = 'RESTORED'").get()?.count || 0;

    return {
      totalPackages,
      activePackages,
      totalSessions,
      activeSessions,
      totalCommands,
      queuedCommands,
      completedCommands,
      failedCommands,
      quarantinedFiles,
      restoredFiles,
      liveResponseAvailable: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve all custom remediation packages with optional filtering
   */
  static getRemediationPackages(db, query = {}) {
    let sql = 'SELECT * FROM custom_remediation_packages WHERE 1=1';
    const params = [];

    if (query.category) {
      sql += ' AND category = ?';
      params.push(query.category);
    }
    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(query.is_active ? 1 : 0);
    }
    if (query.target_scope) {
      sql += ' AND target_scope = ?';
      params.push(query.target_scope);
    }

    sql += ' ORDER BY created_at DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Retrieve single remediation package by ID
   */
  static getRemediationPackageById(db, id) {
    return db.prepare('SELECT * FROM custom_remediation_packages WHERE id = ?').get(id) || null;
  }

  /**
   * Create a new custom remediation package playbook
   */
  static createRemediationPackage(db, data) {
    if (!data.name || !data.detection_script || !data.remediation_script) {
      throw new Error('Name, detection_script, and remediation_script are required');
    }

    const validCategories = ['SECURITY_HARDENING', 'SYSTEM_HEALTH', 'MALWARE_REMEDIATION', 'CONFIG_DRIFT', 'SOFTWARE_REMOVAL', 'CUSTOM'];
    const category = validCategories.includes(data.category) ? data.category : 'SYSTEM_HEALTH';

    const validScriptTypes = ['POWERSHELL', 'BASH', 'PYTHON', 'CMD'];
    const script_type = validScriptTypes.includes(data.script_type) ? data.script_type : 'POWERSHELL';

    const validFrequencies = ['ON_DEMAND', 'HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY'];
    const run_frequency = validFrequencies.includes(data.run_frequency) ? data.run_frequency : 'DAILY';

    const validAccounts = ['SYSTEM', 'CURRENT_USER', 'LOCAL_SERVICE'];
    const run_as_account = validAccounts.includes(data.run_as_account) ? data.run_as_account : 'SYSTEM';

    const id = data.id || ('crp-' + crypto.randomBytes(6).toString('hex'));
    const timeout = parseInt(data.execution_timeout, 10) || 300;
    const enforceSig = data.enforce_signature_check ? 1 : 0;
    const isActive = data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1;

    db.prepare(`
      INSERT INTO custom_remediation_packages (
        id, name, description, category, target_scope, target_id,
        detection_script, remediation_script, script_type, execution_timeout,
        run_frequency, run_as_account, enforce_signature_check, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.name,
      data.description || null,
      category,
      data.target_scope || 'ALL_FLEET',
      data.target_id || null,
      data.detection_script,
      data.remediation_script,
      script_type,
      timeout,
      run_frequency,
      run_as_account,
      enforceSig,
      isActive
    );

    return this.getRemediationPackageById(db, id);
  }

  /**
   * Update an existing custom remediation package
   */
  static updateRemediationPackage(db, id, updates) {
    const existing = this.getRemediationPackageById(db, id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const category = updates.category !== undefined ? updates.category : existing.category;
    const target_scope = updates.target_scope !== undefined ? updates.target_scope : existing.target_scope;
    const target_id = updates.target_id !== undefined ? updates.target_id : existing.target_id;
    const detection_script = updates.detection_script !== undefined ? updates.detection_script : existing.detection_script;
    const remediation_script = updates.remediation_script !== undefined ? updates.remediation_script : existing.remediation_script;
    const script_type = updates.script_type !== undefined ? updates.script_type : existing.script_type;
    const execution_timeout = updates.execution_timeout !== undefined ? parseInt(updates.execution_timeout, 10) : existing.execution_timeout;
    const run_frequency = updates.run_frequency !== undefined ? updates.run_frequency : existing.run_frequency;
    const run_as_account = updates.run_as_account !== undefined ? updates.run_as_account : existing.run_as_account;
    const enforce_signature_check = updates.enforce_signature_check !== undefined ? (updates.enforce_signature_check ? 1 : 0) : existing.enforce_signature_check;
    const is_active = updates.is_active !== undefined ? (updates.is_active ? 1 : 0) : existing.is_active;

    db.prepare(`
      UPDATE custom_remediation_packages SET
        name = ?, description = ?, category = ?, target_scope = ?, target_id = ?,
        detection_script = ?, remediation_script = ?, script_type = ?, execution_timeout = ?,
        run_frequency = ?, run_as_account = ?, enforce_signature_check = ?, is_active = ?,
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(
      name, description, category, target_scope, target_id,
      detection_script, remediation_script, script_type, execution_timeout,
      run_frequency, run_as_account, enforce_signature_check, is_active,
      id
    );

    return this.getRemediationPackageById(db, id);
  }

  /**
   * Delete custom remediation package
   */
  static deleteRemediationPackage(db, id) {
    const res = db.prepare('DELETE FROM custom_remediation_packages WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Start a new interactive Live Response remote investigation session
   */
  static startSession(db, { deviceId, operator = 'SecOps Analyst' }) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error('Device not found');

    const sessionId = 'lrs-' + crypto.randomBytes(6).toString('hex');
    const startedAt = new Date().toISOString();

    return {
      session_id: sessionId,
      device_id: deviceId,
      hostname: device.hostname,
      operator,
      started_at: startedAt
    };
  }

  /**
   * Queue a Live Response command for endpoint execution
   */
  static queueCommand(db, { sessionId, deviceId, commandType, commandPayload, operator = 'SecOps Analyst' }) {
    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error('Device not found');

    const validTypes = ['EXEC_POWERSHELL', 'EXEC_CMD', 'GET_FILE', 'PUT_FILE', 'TERMINATE_PROCESS', 'ISOLATE_HOST', 'RESTORE_HOST', 'LIST_DIRECTORY', 'PROCESS_DUMP', 'REGISTRY_QUERY'];
    if (!validTypes.includes(commandType)) {
      throw new Error(`Invalid commandType: ${commandType}. Allowed: ${validTypes.join(', ')}`);
    }

    if (!commandPayload) {
      throw new Error('commandPayload is required');
    }

    const id = 'lrc-' + crypto.randomBytes(6).toString('hex');

    db.prepare(`
      INSERT INTO live_response_command_sessions (
        id, session_id, device_id, hostname, operator,
        command_type, command_payload, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'QUEUED')
    `).run(
      id,
      sessionId || ('lrs-' + crypto.randomBytes(6).toString('hex')),
      deviceId,
      device.hostname,
      operator,
      commandType,
      commandPayload
    );

    // Audit critical commands in security_events
    if (['TERMINATE_PROCESS', 'ISOLATE_HOST'].includes(commandType)) {
      try {
        db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
          ) VALUES (?, 'MALWARE_THREAT_DETECTED', 7006, 'LIVE_RESPONSE_ENGINE', 'HIGH', ?, ?, 0)
        `).run(
          deviceId,
          `Live Response action [${commandType}] dispatched by ${operator} on ${device.hostname}`,
          JSON.stringify({ command_id: id, command_type: commandType, payload: commandPayload })
        );
      } catch {}
    }

    return db.prepare('SELECT * FROM live_response_command_sessions WHERE id = ?').get(id);
  }

  /**
   * Get all commands in an active or historical session
   */
  static getSessionCommands(db, sessionId) {
    return db.prepare('SELECT * FROM live_response_command_sessions WHERE session_id = ? ORDER BY queued_at ASC').all(sessionId);
  }

  /**
   * Node agent poll: Retrieve pending queued commands for this device and mark IN_PROGRESS
   */
  static getPendingCommandsForDevice(db, deviceId) {
    const commands = db.prepare(`
      SELECT * FROM live_response_command_sessions
      WHERE device_id = ? AND status = 'QUEUED'
      ORDER BY queued_at ASC
    `).all(deviceId);

    if (commands.length > 0) {
      const updateStmt = db.prepare(`
        UPDATE live_response_command_sessions
        SET status = 'IN_PROGRESS', executed_at = DATETIME('now')
        WHERE id = ?
      `);
      for (const cmd of commands) {
        updateStmt.run(cmd.id);
      }
    }

    return commands;
  }

  /**
   * Node agent completion: Mark command completed or failed with output & exit code
   */
  static completeCommand(db, commandId, { output = '', exitCode = 0, status = 'COMPLETED', durationMs = null } = {}) {
    const existing = db.prepare('SELECT * FROM live_response_command_sessions WHERE id = ?').get(commandId);
    if (!existing) throw new Error('Command session record not found');

    const validStatuses = ['COMPLETED', 'FAILED', 'TIMED_OUT', 'CANCELLED'];
    const finalStatus = validStatuses.includes(status) ? status : (exitCode === 0 ? 'COMPLETED' : 'FAILED');

    db.prepare(`
      UPDATE live_response_command_sessions SET
        status = ?,
        output = ?,
        exit_code = ?,
        duration_ms = ?,
        completed_at = DATETIME('now')
      WHERE id = ?
    `).run(
      finalStatus,
      output !== null ? String(output) : '',
      exitCode !== null ? parseInt(exitCode, 10) : 0,
      durationMs !== null ? parseInt(durationMs, 10) : null,
      commandId
    );

    return db.prepare('SELECT * FROM live_response_command_sessions WHERE id = ?').get(commandId);
  }

  /**
   * Quarantine a suspicious or malicious file into the secure vault
   */
  static quarantineFile(db, data = {}) {
    const deviceId = data.deviceId || data.device_id;
    const originalPath = data.originalPath || data.original_path;
    const fileName = data.fileName || data.file_name;
    const sha256Hash = data.sha256Hash || data.sha256_hash;
    const fileSizeBytes = data.fileSizeBytes !== undefined ? data.fileSizeBytes : (data.file_size_bytes !== undefined ? data.file_size_bytes : 0);
    const threatName = data.threatName || data.threat_name || 'Suspicious.Generic';
    const quarantinedBy = data.quarantinedBy || data.quarantined_by || 'SecOps Analyst';
    const notes = data.notes || null;

    const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(deviceId);
    if (!device) throw new Error('Device not found');

    if (!originalPath || !fileName) {
      throw new Error('originalPath and fileName are required');
    }

    const hash = sha256Hash || crypto.createHash('sha256').update(originalPath + Date.now()).digest('hex');
    const id = 'qfi-' + crypto.randomBytes(6).toString('hex');
    const vaultPath = `C:\\ProgramData\\LocalPilotFleet\\Quarantine\\${hash.slice(0, 16)}.vault`;

    db.prepare(`
      INSERT INTO quarantined_files_inventory (
        id, device_id, hostname, original_path, file_name,
        sha256_hash, file_size_bytes, threat_name, quarantined_by,
        quarantine_vault_path, status, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'QUARANTINED', ?)
    `).run(
      id,
      deviceId,
      device.hostname,
      originalPath,
      fileName,
      hash,
      parseInt(fileSizeBytes, 10) || 0,
      threatName,
      quarantinedBy,
      vaultPath,
      notes
    );

    // Emitting security alert
    try {
      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
        ) VALUES (?, 'MALWARE_THREAT_DETECTED', 7005, 'LIVE_RESPONSE_ENGINE', 'CRITICAL', ?, ?, 0)
      `).run(
        deviceId,
        `Threat Quarantined: ${fileName} (${threatName}) on ${device.hostname}`,
        JSON.stringify({ quarantine_id: id, original_path: originalPath, sha256: hash, vault_path: vaultPath })
      );
    } catch {}

    return db.prepare('SELECT * FROM quarantined_files_inventory WHERE id = ?').get(id);
  }

  /**
   * Restore a previously quarantined file back to its original location
   */
  static restoreFile(db, id, { restoredBy = 'SecOps Analyst', notes = null } = {}) {
    const existing = db.prepare('SELECT * FROM quarantined_files_inventory WHERE id = ?').get(id);
    if (!existing) throw new Error('Quarantined file not found');

    const updatedNotes = notes ? `${existing.notes ? existing.notes + ' | ' : ''}Restored by ${restoredBy}: ${notes}` : existing.notes;

    db.prepare(`
      UPDATE quarantined_files_inventory SET
        status = 'RESTORED',
        restored_at = DATETIME('now'),
        notes = ?
      WHERE id = ?
    `).run(updatedNotes, id);

    return db.prepare('SELECT * FROM quarantined_files_inventory WHERE id = ?').get(id);
  }

  /**
   * Get quarantined files inventory with optional query filters
   */
  static getQuarantinedFiles(db, query = {}) {
    let sql = 'SELECT * FROM quarantined_files_inventory WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.status) {
      sql += ' AND status = ?';
      params.push(query.status);
    }
    if (query.threat_name) {
      sql += ' AND threat_name LIKE ?';
      params.push(`%${query.threat_name}%`);
    }

    sql += ' ORDER BY quarantined_at DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Generate an end-to-end execution wrapper PowerShell script for a remediation package
   */
  static generateRemediationScript(db, packageId) {
    const pkg = this.getRemediationPackageById(db, packageId);
    if (!pkg) throw new Error('Remediation package not found');

    return `# ==============================================================================
# LocalPilot Fleet — Automated Remediation Playbook Wrapper
# Package: ${pkg.name} (${pkg.id})
# Category: ${pkg.category} | Frequency: ${pkg.run_frequency} | Target: ${pkg.target_scope}
# Generated: ${new Date().toISOString()}
# ==============================================================================

\$ErrorActionPreference = 'Stop'
\$remediationResult = @{
    PackageId = "${pkg.id}"
    PackageName = "${pkg.name}"
    Category = "${pkg.category}"
    ExecutionTime = (Get-Date).ToString("o")
    DetectionExitCode = 0
    RemediationExecuted = \$false
    Success = \$true
    Log = @()
}

Write-Host "[LocalPilot-Remediation] Starting Playbook: ${pkg.name}" -ForegroundColor Cyan

# 1. Detection Phase
try {
    Write-Host "[LocalPilot-Remediation] Executing Detection Script..." -ForegroundColor Yellow
    \$detectionBlock = {
        ${pkg.detection_script}
    }
    & \$detectionBlock
    \$detectExit = \$LASTEXITCODE
    if (\$null -eq \$detectExit) { \$detectExit = 0 }
    \$remediationResult.DetectionExitCode = \$detectExit
} catch {
    \$remediationResult.DetectionExitCode = 1
    \$remediationResult.Log += "Detection script exception: \$_"
    \$detectExit = 1
}

# Exit code 1 indicates non-compliance requiring remediation
if (\$detectExit -ne 0) {
    Write-Host "[LocalPilot-Remediation] Non-compliance detected (Code \$detectExit). Executing Remediation..." -ForegroundColor Magenta
    \$remediationResult.RemediationExecuted = \$true
    try {
        \$remediationBlock = {
            ${pkg.remediation_script}
        }
        & \$remediationBlock
        \$remediationResult.Log += "Remediation logic executed successfully."
        Write-Host "[LocalPilot-Remediation] Remediation applied successfully." -ForegroundColor Green
    } catch {
        \$remediationResult.Success = \$false
        \$remediationResult.Log += "Remediation failure: \$_"
        Write-Host "[LocalPilot-Remediation] ERROR executing remediation: \$_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[LocalPilot-Remediation] Endpoint is fully compliant. No remediation action needed." -ForegroundColor Green
    \$remediationResult.Log += "Compliant state confirmed."
}

# Output JSON summary for agent ingestion
ConvertTo-Json -InputObject \$remediationResult -Compress
`;
  }
}
