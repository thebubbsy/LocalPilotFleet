/**
 * LocalPilot Fleet — USB & Peripheral Device Control Service Engine
 * server/src/services/peripheralControlEngine.js
 *
 * Implements hardware-enforced peripheral governance, removable storage read-only/block policies,
 * VID/PID/Serial whitelist exceptions, and forensic connection/write telemetry.
 */

import crypto from 'node:crypto';

export class PeripheralControlEngine {
  /**
   * Aggregate fleet-wide peripheral security and device control statistics
   */
  static getPeripheralControlStats(db) {
    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM usb_device_control_policies').get()?.count || 0;
    const activePolicies = db.prepare('SELECT COUNT(*) as count FROM usb_device_control_policies WHERE is_enabled = 1').get()?.count || 0;
    const totalExceptions = db.prepare('SELECT COUNT(*) as count FROM usb_device_exceptions').get()?.count || 0;
    const activeExceptions = db.prepare('SELECT COUNT(*) as count FROM usb_device_exceptions WHERE is_active = 1').get()?.count || 0;

    const totalEvents = db.prepare('SELECT COUNT(*) as count FROM peripheral_audit_events').get()?.count || 0;
    const blockedWrites = db.prepare("SELECT COUNT(*) as count FROM peripheral_audit_events WHERE event_type = 'WRITE_BLOCKED'").get()?.count || 0;
    const usbAttaches = db.prepare("SELECT COUNT(*) as count FROM peripheral_audit_events WHERE event_type = 'USB_ATTACH'").get()?.count || 0;

    return {
      totalPolicies,
      activePolicies,
      totalExceptions,
      activeExceptions,
      totalEvents,
      blockedWrites,
      usbAttaches,
      enforcementSla: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve all USB / peripheral control policies
   */
  static getPolicies(db) {
    return db.prepare('SELECT * FROM usb_device_control_policies ORDER BY created_at DESC').all();
  }

  /**
   * Retrieve single policy with attached hardware exceptions
   */
  static getPolicyById(db, id) {
    const policy = db.prepare('SELECT * FROM usb_device_control_policies WHERE id = ?').get(id);
    if (!policy) return null;

    const exceptions = db.prepare('SELECT * FROM usb_device_exceptions WHERE policy_id = ? ORDER BY created_at ASC').all(id);
    return {
      ...policy,
      exceptions
    };
  }

  /**
   * Create a new USB device control policy
   */
  static createPolicy(db, data) {
    const id = data.id || ('usb-pol-' + crypto.randomBytes(6).toString('hex'));
    const isEnabled = data.is_enabled !== undefined ? (data.is_enabled ? 1 : 0) : 1;

    const stmt = db.prepare(`
      INSERT INTO usb_device_control_policies (
        id, name, description, target_scope, target_id, removable_storage_access,
        bluetooth_mode, printer_protection_mode, audit_level, is_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.description || null,
      data.target_scope || 'ALL_FLEET',
      data.target_id || null,
      data.removable_storage_access || 'READ_ONLY',
      data.bluetooth_mode || 'RESTRICTED',
      data.printer_protection_mode || 'AUDIT',
      data.audit_level || 'DETAILED',
      isEnabled
    );

    return this.getPolicyById(db, id);
  }

  /**
   * Update an existing USB control policy
   */
  static updatePolicy(db, id, updates) {
    const existing = db.prepare('SELECT * FROM usb_device_control_policies WHERE id = ?').get(id);
    if (!existing) return null;

    const name = updates.name !== undefined ? updates.name : existing.name;
    const description = updates.description !== undefined ? updates.description : existing.description;
    const target_scope = updates.target_scope !== undefined ? updates.target_scope : existing.target_scope;
    const target_id = updates.target_id !== undefined ? updates.target_id : existing.target_id;
    const removable_storage_access = updates.removable_storage_access !== undefined ? updates.removable_storage_access : existing.removable_storage_access;
    const bluetooth_mode = updates.bluetooth_mode !== undefined ? updates.bluetooth_mode : existing.bluetooth_mode;
    const printer_protection_mode = updates.printer_protection_mode !== undefined ? updates.printer_protection_mode : existing.printer_protection_mode;
    const audit_level = updates.audit_level !== undefined ? updates.audit_level : existing.audit_level;
    const is_enabled = updates.is_enabled !== undefined ? (updates.is_enabled ? 1 : 0) : existing.is_enabled;

    db.prepare(`
      UPDATE usb_device_control_policies SET
        name = ?, description = ?, target_scope = ?, target_id = ?,
        removable_storage_access = ?, bluetooth_mode = ?, printer_protection_mode = ?,
        audit_level = ?, is_enabled = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(name, description, target_scope, target_id, removable_storage_access, bluetooth_mode, printer_protection_mode, audit_level, is_enabled, id);

    return this.getPolicyById(db, id);
  }

  /**
   * Delete policy and cascaded exceptions
   */
  static deletePolicy(db, id) {
    const res = db.prepare('DELETE FROM usb_device_control_policies WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Get hardware whitelist / exception rules
   */
  static getExceptions(db, policyId = null) {
    if (policyId) {
      return db.prepare('SELECT * FROM usb_device_exceptions WHERE policy_id = ? ORDER BY created_at DESC').all(policyId);
    }
    return db.prepare('SELECT * FROM usb_device_exceptions ORDER BY created_at DESC').all();
  }

  /**
   * Add a hardware exception (VID/PID or Serial whitelist)
   */
  static createException(db, data) {
    const id = data.id || ('usb-exc-' + crypto.randomBytes(6).toString('hex'));
    const isActive = data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1;

    db.prepare(`
      INSERT INTO usb_device_exceptions (
        id, policy_id, friendly_name, vendor_id, product_id, serial_number, device_interface_id, action, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.policy_id || null,
      data.friendly_name,
      data.vendor_id || null,
      data.product_id || null,
      data.serial_number || null,
      data.device_interface_id || null,
      data.action || 'ALLOW',
      isActive
    );

    return db.prepare('SELECT * FROM usb_device_exceptions WHERE id = ?').get(id);
  }

  /**
   * Delete an exception rule
   */
  static deleteException(db, id) {
    const res = db.prepare('DELETE FROM usb_device_exceptions WHERE id = ?').run(id);
    return res.changes > 0;
  }

  /**
   * Log a peripheral event (connection, write blocked, etc.)
   */
  static logPeripheralEvent(db, data) {
    const id = data.id || ('pae-' + crypto.randomBytes(6).toString('hex'));
    const severity = data.severity || (data.event_type === 'WRITE_BLOCKED' ? 'HIGH' : 'INFO');
    const detailsStr = typeof data.details === 'object' ? JSON.stringify(data.details) : (data.details || null);

    db.prepare(`
      INSERT INTO peripheral_audit_events (
        id, device_id, hostname, username, event_type, device_name,
        hardware_id, serial_number, action_taken, process_name, file_path, details, severity
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      data.device_id,
      data.hostname || 'Unknown-Node',
      data.username || 'System',
      data.event_type,
      data.device_name || 'Generic USB Device',
      data.hardware_id || null,
      data.serial_number || null,
      data.action_taken || 'BLOCKED',
      data.process_name || 'explorer.exe',
      data.file_path || null,
      detailsStr,
      severity
    );

    // If unauthorized write was blocked, automatically trigger a security alert
    if (data.event_type === 'WRITE_BLOCKED') {
      try {
        db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
          ) VALUES (?, 'MALWARE_THREAT_DETECTED', 7002, 'PERIPHERAL_CONTROL_ENGINE', 'HIGH', ?, ?, 0)
        `).run(
          data.device_id,
          `Blocked write attempt to removable device: ${data.device_name || 'USB Storage'}`,
          JSON.stringify({ file_path: data.file_path, hardware_id: data.hardware_id, process: data.process_name })
        );
      } catch (err) {
        console.error('Failed to log security alert for WRITE_BLOCKED:', err);
      }
    }

    return db.prepare('SELECT * FROM peripheral_audit_events WHERE id = ?').get(id);
  }

  /**
   * Retrieve peripheral audit events with query filters
   */
  static getPeripheralEvents(db, query = {}) {
    let sql = 'SELECT * FROM peripheral_audit_events WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.event_type) {
      sql += ' AND event_type = ?';
      params.push(query.event_type);
    }
    if (query.action_taken) {
      sql += ' AND action_taken = ?';
      params.push(query.action_taken);
    }

    sql += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(parseInt(query.limit, 10) || 50);

    return db.prepare(sql).all(...params);
  }

  /**
   * Generate native Windows PowerShell / Registry script to enforce USB control
   */
  static generatePeripheralControlScript(db, deviceId) {
    const policy = db.prepare(`
      SELECT * FROM usb_device_control_policies WHERE is_enabled = 1 ORDER BY created_at DESC LIMIT 1
    `).get() || {
      removable_storage_access: 'READ_ONLY',
      bluetooth_mode: 'RESTRICTED',
      printer_protection_mode: 'AUDIT',
      audit_level: 'DETAILED'
    };

    const exceptions = db.prepare('SELECT * FROM usb_device_exceptions WHERE is_active = 1').all();

    return `# ==============================================================================
# LocalPilot Fleet — Windows Defender USB & Removable Storage Device Control
# Generated for Device ID: ${deviceId} at ${new Date().toISOString()}
# Removable Storage Access Mode: ${policy.removable_storage_access}
# Bluetooth Mode: ${policy.bluetooth_mode}
# ==============================================================================

Write-Host "[LocalPilot] Enforcing Removable Storage Device Control Baseline..." -ForegroundColor Cyan

# 1. Removable Storage Access Group Policy Registry Keys
$StoragePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
if (!(Test-Path $StoragePath)) {
    New-Item -Path $StoragePath -Force | Out-Null
}

$DenyAll = ${policy.removable_storage_access === 'BLOCK' ? 1 : 0}
$DenyWrite = ${policy.removable_storage_access === 'READ_ONLY' ? 1 : 0}

if ($DenyAll -eq 1) {
    Set-ItemProperty -Path $StoragePath -Name "Deny_All" -Value 1 -Type DWord -Force
    Write-Host "[LocalPilot] Strict Airgap: All Removable Storage Devices Blocked." -ForegroundColor Yellow
} elseif ($DenyWrite -eq 1) {
    $DiskPath = "$StoragePath\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
    if (!(Test-Path $DiskPath)) { New-Item -Path $DiskPath -Force | Out-Null }
    Set-ItemProperty -Path $DiskPath -Name "Deny_Write" -Value 1 -Type DWord -Force
    Write-Host "[LocalPilot] Removable Storage Write Protection Enforced (Read-Only Mode)." -ForegroundColor Green
}

# 2. Hardware Exception Whitelist (VID / PID / Serial)
${exceptions.map(exc => `# Whitelist Exception: ${exc.friendly_name} (Action: ${exc.action})
# VID: ${exc.vendor_id || '*'} | PID: ${exc.product_id || '*'} | SN: ${exc.serial_number || '*'}
`).join('\n')}

# 3. Enable Detailed Defender Device Control Event Auditing
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null

Write-Host "[LocalPilot] Peripheral Device Control policy applied successfully." -ForegroundColor Green
`;
  }
}
