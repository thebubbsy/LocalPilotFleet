/**
 * LocalPilot Fleet — Unified Endpoint Management (UEM) Multi-Platform Engine
 * server/src/services/multiPlatformUemEngine.js
 *
 * Provides cross-platform fleet enrollment, Apple MDM (.mobileconfig) profile generation,
 * Android Enterprise QR provisioning, remote mobile command queue, and platform compliance auditing.
 */

import crypto from 'node:crypto';

export class MultiPlatformUemEngine {
  /**
   * Helper to normalize OS string to standardized platform category
   */
  static detectPlatform(osName = '') {
    const os = osName.toLowerCase();
    if (os.includes('macos') || os.includes('darwin') || os.includes('mac os')) return 'MACOS';
    if (os.includes('ios') || os.includes('ipados') || os.includes('iphone')) return 'IOS';
    if (os.includes('android')) return 'ANDROID';
    if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('rhel')) return 'LINUX';
    return 'WINDOWS';
  }

  /**
   * Aggregate multi-platform fleet distribution and UEM KPIs
   */
  static getPlatformStats(db) {
    const devices = db.prepare('SELECT os_name, status FROM devices').all();

    let windows = 0;
    let macos = 0;
    let ios = 0;
    let android = 0;
    let linux = 0;

    for (const d of devices) {
      const plat = this.detectPlatform(d.os_name);
      if (plat === 'WINDOWS') windows++;
      else if (plat === 'MACOS') macos++;
      else if (plat === 'IOS') ios++;
      else if (plat === 'ANDROID') android++;
      else if (plat === 'LINUX') linux++;
    }

    const appleProfRow = db.prepare('SELECT COUNT(*) as count FROM apple_mdm_enrollment_profiles WHERE is_active = 1').get();
    const androidProfRow = db.prepare('SELECT COUNT(*) as count FROM android_enterprise_profiles WHERE is_active = 1').get();
    const pendingCmdRow = db.prepare("SELECT COUNT(*) as count FROM mobile_device_commands WHERE status = 'PENDING'").get();

    return {
      totalDevices: devices.length,
      windowsDevices: windows,
      macosDevices: macos,
      iosDevices: ios,
      androidDevices: android,
      linuxDevices: linux,
      totalNonWindows: macos + ios + android + linux,
      activeAppleProfiles: appleProfRow?.count || 0,
      activeAndroidProfiles: androidProfRow?.count || 0,
      pendingCommands: pendingCmdRow?.count || 0,
      uemOperational: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve multi-platform devices with normalized platform badge
   */
  static getMultiplatformDevices(db, query = {}) {
    let sql = 'SELECT * FROM devices WHERE 1=1';
    const params = [];

    if (query.status) {
      sql += ' AND status = ?';
      params.push(query.status);
    }
    if (query.search) {
      sql += ' AND (hostname LIKE ? OR friendly_name LIKE ? OR os_name LIKE ? OR serial_number LIKE ?)';
      const s = `%${query.search}%`;
      params.push(s, s, s, s);
    }

    sql += ' ORDER BY last_seen_at DESC';
    const rows = db.prepare(sql).all(...params);

    const mapped = rows.map(r => {
      const platform = this.detectPlatform(r.os_name);
      return { ...r, platform };
    });

    if (query.platform) {
      const targetPlat = query.platform.toUpperCase();
      return mapped.filter(m => m.platform === targetPlat);
    }

    return mapped;
  }

  /**
   * Enroll non-Windows device (macOS, iOS, Android, Linux)
   */
  static enrollMobileDevice(db, data) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

    const id = data.device_id || ('dev-' + crypto.randomBytes(4).toString('hex'));
    const hostname = data.hostname || (`${data.platform || 'MOBILE'}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`);
    const osName = data.os_name || data.platform || 'macOS';
    const osVersion = data.os_version || '14.0';

    const existing = db.prepare('SELECT id FROM devices WHERE id = ? OR (serial_number IS NOT NULL AND serial_number = ?)').get(
      id,
      data.serial_number || null
    );

    if (existing) {
      db.prepare(`
        UPDATE devices SET
          hostname = ?,
          os_name = ?,
          os_version = ?,
          cpu_model = COALESCE(?, cpu_model),
          total_ram_bytes = COALESCE(?, total_ram_bytes),
          status = 'online',
          node_token_hash = ?,
          last_seen_at = DATETIME('now'),
          updated_at = DATETIME('now')
        WHERE id = ?
      `).run(
        hostname,
        osName,
        osVersion,
        data.cpu_model || null,
        data.total_ram_bytes || 8589934592,
        tokenHash,
        existing.id
      );

      return {
        device_id: existing.id,
        hostname,
        token: rawToken,
        node_token: rawToken,
        platform: this.detectPlatform(osName),
        is_new: false
      };
    } else {
      const stmt = db.prepare(`
        INSERT INTO devices (
          id, hostname, friendly_name, serial_number, uuid, mac_address,
          os_name, os_version, os_build, os_architecture, cpu_model, total_ram_bytes,
          status, connection_route, node_token_hash, agent_version, primary_user
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', 'LAN', ?, ?, ?)
      `);

      stmt.run(
        id,
        hostname,
        data.friendly_name || hostname,
        data.serial_number || ('SN-' + crypto.randomBytes(4).toString('hex').toUpperCase()),
        data.uuid || crypto.randomUUID(),
        data.mac_address || '00:00:00:00:00:00',
        osName,
        osVersion,
        data.os_build || '23A344',
        data.os_architecture || 'arm64',
        data.cpu_model || 'Apple M2 / Snapdragon / ARM',
        data.total_ram_bytes || 8589934592,
        tokenHash,
        data.agent_version || '2.0.0-uem',
        data.primary_user || 'mobile_user@localpilot.corp'
      );

      return {
        device_id: id,
        hostname,
        token: rawToken,
        node_token: rawToken,
        platform: this.detectPlatform(osName),
        is_new: true
      };
    }
  }

  /**
   * List Apple MDM profiles
   */
  static getAppleProfiles(db, query = {}) {
    let sql = 'SELECT * FROM apple_mdm_enrollment_profiles WHERE 1=1';
    const params = [];

    if (query.target_platform) {
      sql += ' AND (target_platform = ? OR target_platform = \'COMBINED\')';
      params.push(query.target_platform);
    }
    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(query.is_active ? 1 : 0);
    }

    return db.prepare(sql).all(...params);
  }

  /**
   * Create Apple MDM profile
   */
  static createAppleProfile(db, data) {
    const id = data.id || ('amp-' + crypto.randomBytes(4).toString('hex'));
    const uuid = data.payload_uuid || crypto.randomUUID().toUpperCase();
    const passcodeJson = typeof data.passcode_policy === 'string' ? data.passcode_policy : JSON.stringify(data.passcode_policy || {});

    const stmt = db.prepare(`
      INSERT INTO apple_mdm_enrollment_profiles (
        id, name, target_platform, organization_name, payload_identifier,
        payload_uuid, passcode_policy_json, filevault_enabled, filevault_escrow_enabled,
        wifi_ssid, wifi_encryption_type, is_supervised, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.target_platform || 'COMBINED',
      data.organization_name || 'LocalPilot Enterprise',
      data.payload_identifier || ('corp.localpilot.mdm.' + id),
      uuid,
      passcodeJson,
      data.filevault_enabled !== undefined ? (data.filevault_enabled ? 1 : 0) : 1,
      data.filevault_escrow_enabled !== undefined ? (data.filevault_escrow_enabled ? 1 : 0) : 1,
      data.wifi_ssid || null,
      data.wifi_encryption_type || 'WPA2',
      data.is_supervised !== undefined ? (data.is_supervised ? 1 : 0) : 1,
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return db.prepare('SELECT * FROM apple_mdm_enrollment_profiles WHERE id = ?').get(id);
  }

  /**
   * Generate Apple standard XML Property List (.mobileconfig)
   */
  static generateAppleMdmProfile(db, profileId) {
    const profile = db.prepare('SELECT * FROM apple_mdm_enrollment_profiles WHERE id = ?').get(profileId);
    if (!profile) return null;

    let passcode = {};
    try { passcode = JSON.parse(profile.passcode_policy_json || '{}'); } catch {}

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDescription</key>
    <string>${profile.name}</string>
    <key>PayloadDisplayName</key>
    <string>${profile.name}</string>
    <key>PayloadIdentifier</key>
    <string>${profile.payload_identifier}</string>
    <key>PayloadOrganization</key>
    <string>${profile.organization_name}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${profile.payload_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
        <!-- Passcode Restrictions Payload -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.mobiledevice.passwordpolicy</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>${profile.payload_identifier}.passwordpolicy</string>
            <key>PayloadUUID</key>
            <string>${crypto.randomUUID().toUpperCase()}</string>
            <key>PayloadEnabled</key>
            <true/>
            <key>minLength</key>
            <integer>${passcode.minLength || 8}</integer>
            <key>requireAlphanumeric</key>
            <${passcode.requireAlphanumeric ? 'true' : 'false'}/>
            <key>maxFailedAttempts</key>
            <integer>${passcode.maxFailedAttempts || 5}</integer>
        </dict>
        <!-- FileVault Escrow (macOS) Payload -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.MCX.FileVault2</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>${profile.payload_identifier}.filevault</string>
            <key>PayloadUUID</key>
            <string>${crypto.randomUUID().toUpperCase()}</string>
            <key>PayloadEnabled</key>
            <${profile.filevault_enabled ? 'true' : 'false'}/>
            <key>Defer</key>
            <true/>
            <key>Enable</key>
            <string>On</string>
            <key>ShowRecoveryKey</key>
            <false/>
        </dict>
    </array>
</dict>
</plist>`;

    return {
      id: profile.id,
      name: profile.name,
      filename: `${profile.payload_identifier}.mobileconfig`,
      content_type: 'application/x-apple-aspen-config',
      plist_xml: xml
    };
  }

  /**
   * List Android Enterprise profiles
   */
  static getAndroidProfiles(db, query = {}) {
    let sql = 'SELECT * FROM android_enterprise_profiles WHERE 1=1';
    const params = [];

    if (query.enrollment_mode) {
      sql += ' AND enrollment_mode = ?';
      params.push(query.enrollment_mode);
    }
    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(query.is_active ? 1 : 0);
    }

    return db.prepare(sql).all(...params);
  }

  /**
   * Create Android Enterprise profile
   */
  static createAndroidProfile(db, data) {
    const id = data.id || ('aep-' + crypto.randomBytes(4).toString('hex'));
    const token = data.enrollment_token || ('LP-AND-' + crypto.randomBytes(6).toString('hex').toUpperCase());

    const qrPayload = {
      "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "corp.localpilot.mdm/.DeviceAdminReceiver",
      "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME": "corp.localpilot.mdm",
      "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": {
        "server_url": data.server_url || "https://fleet.localpilot.internal:8443",
        "enrollment_token": token,
        "mode": data.enrollment_mode || "FULLY_MANAGED"
      }
    };

    const stmt = db.prepare(`
      INSERT INTO android_enterprise_profiles (
        id, name, enrollment_mode, enrollment_token, qr_code_payload_json,
        camera_disabled, screen_capture_disabled, usb_debugging_disabled,
        storage_encryption_required, minimum_android_version, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.enrollment_mode || 'FULLY_MANAGED',
      token,
      JSON.stringify(qrPayload),
      data.camera_disabled ? 1 : 0,
      data.screen_capture_disabled ? 1 : 0,
      data.usb_debugging_disabled !== undefined ? (data.usb_debugging_disabled ? 1 : 0) : 1,
      data.storage_encryption_required !== undefined ? (data.storage_encryption_required ? 1 : 0) : 1,
      data.minimum_android_version || '12.0',
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return db.prepare('SELECT * FROM android_enterprise_profiles WHERE id = ?').get(id);
  }

  /**
   * Retrieve Android QR provisioning payload
   */
  static generateAndroidQrPayload(db, profileId) {
    const profile = db.prepare('SELECT * FROM android_enterprise_profiles WHERE id = ?').get(profileId);
    if (!profile) return null;

    let payload = {};
    try { payload = JSON.parse(profile.qr_code_payload_json || '{}'); } catch {}

    return {
      profile_id: profile.id,
      name: profile.name,
      enrollment_mode: profile.enrollment_mode,
      enrollment_token: profile.enrollment_token,
      qr_payload: payload
    };
  }

  /**
   * Dispatch remote management command to non-Windows device
   */
  static dispatchDeviceCommand(db, data) {
    const id = data.id || ('mdc-' + crypto.randomBytes(4).toString('hex'));
    const device = db.prepare('SELECT id, os_name FROM devices WHERE id = ?').get(data.device_id);
    if (!device) throw new Error('Target device not found');

    const platform = data.platform || this.detectPlatform(device.os_name);
    const paramsJson = typeof data.command_params === 'string' ? data.command_params : JSON.stringify(data.command_params || {});

    const stmt = db.prepare(`
      INSERT INTO mobile_device_commands (
        id, device_id, platform, command_type, command_params_json, status, issued_by
      ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
    `);

    stmt.run(
      id,
      data.device_id,
      platform,
      data.command_type,
      paramsJson,
      data.issued_by || 'Security Admin'
    );

    return db.prepare('SELECT * FROM mobile_device_commands WHERE id = ?').get(id);
  }

  /**
   * Retrieve command history for a device
   */
  static getDeviceCommands(db, deviceId) {
    return db.prepare('SELECT * FROM mobile_device_commands WHERE device_id = ? ORDER BY issued_at DESC').all(deviceId);
  }

  /**
   * Client retrieves pending commands
   */
  static getPendingCommands(db, deviceId) {
    const rows = db.prepare("SELECT * FROM mobile_device_commands WHERE device_id = ? AND status = 'PENDING' ORDER BY issued_at ASC").all(deviceId);
    return rows.map(r => {
      let params = {};
      try { params = JSON.parse(r.command_params_json || '{}'); } catch {}
      return { ...r, command_params: params };
    });
  }

  /**
   * Client acknowledges execution of a command
   */
  static acknowledgeCommand(db, commandId, resultDetails = {}) {
    const detailsJson = typeof resultDetails === 'string' ? resultDetails : JSON.stringify(resultDetails || {});

    db.prepare(`
      UPDATE mobile_device_commands SET
        status = 'ACKNOWLEDGED',
        executed_at = DATETIME('now'),
        result_details_json = ?
      WHERE id = ?
    `).run(detailsJson, commandId);

    return db.prepare('SELECT * FROM mobile_device_commands WHERE id = ?').get(commandId);
  }

  /**
   * Multi-platform compliance assessment
   */
  static evaluatePlatformCompliance(db, deviceId, telemetry = {}) {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
    if (!device) return { compliant: false, reasons: ['Device not found'] };

    const platform = this.detectPlatform(device.os_name);
    const violations = [];

    if (platform === 'MACOS') {
      if (telemetry.sip_enabled === false) {
        violations.push('System Integrity Protection (SIP) is disabled');
      }
      if (telemetry.filevault_enabled === false) {
        violations.push('FileVault 2 full-disk encryption is inactive');
      }
      if (telemetry.gatekeeper_enabled === false) {
        violations.push('macOS Gatekeeper application validation is disabled');
      }
    } else if (platform === 'IOS') {
      if (telemetry.is_jailbroken === true) {
        violations.push('CRITICAL: iOS jailbreak detected (Cydia/checkra1n/Substrate binaries found)');
      }
      if (telemetry.passcode_set === false) {
        violations.push('Device passcode is not configured');
      }
    } else if (platform === 'ANDROID') {
      if (telemetry.is_rooted === true) {
        violations.push('CRITICAL: Android root privilege escalation detected (su/Magisk binary present)');
      }
      if (telemetry.storage_encrypted === false) {
        violations.push('Android device storage encryption is disabled');
      }
      if (telemetry.play_integrity_valid === false) {
        violations.push('Google Play Integrity / Samsung Knox hardware attestation failed');
      }
    }

    return {
      compliant: violations.length === 0,
      platform,
      violations
    };
  }
}
