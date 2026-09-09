/**
 * server/src/services/whfbEngine.js
 * 
 * Windows Hello for Business (WHfB) & FIDO2 Passwordless Authentication Governance Engine.
 * Implements Intune-grade PIN complexity enforcement, TPM key attestation,
 * biometric anti-spoofing verification, and FIDO2 WebAuthn credential management.
 */

import { randomUUID } from 'node:crypto';

/**
 * Get all WHfB policies with assigned device count
 */
export function getWhfbPolicies(db) {
  const policies = db.prepare(`
    SELECT p.*, g.name as target_group_name,
      (SELECT COUNT(*) FROM device_whfb_status dws WHERE dws.policy_id = p.id) as assigned_devices_count
    FROM whfb_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    ORDER BY p.created_at ASC
  `).all();
  return policies;
}

/**
 * Get a single WHfB policy by ID
 */
export function getWhfbPolicy(db, id) {
  const policy = db.prepare(`
    SELECT p.*, g.name as target_group_name
    FROM whfb_policies p
    LEFT JOIN dynamic_groups g ON p.target_group_id = g.id
    WHERE p.id = ?
  `).get(id);
  return policy || null;
}

/**
 * Create a new WHfB policy
 */
export function createWhfbPolicy(db, data) {
  const id = data.id || `whfb-pol-${randomUUID().slice(0, 8)}`;
  const stmt = db.prepare(`
    INSERT INTO whfb_policies (
      id, name, description, target_group_id, state,
      min_pin_length, max_pin_length, pin_uppercase, pin_lowercase,
      pin_special_chars, pin_digits, pin_expiration_days, pin_history_count,
      allow_biometrics, require_enhanced_anti_spoofing, use_tpm_only,
      allow_fido2_security_keys, enabled, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, DATETIME('now'), DATETIME('now')
    )
  `);

  stmt.run(
    id,
    data.name || 'Custom WHfB Policy',
    data.description || '',
    data.target_group_id || 'grp-all',
    data.state || 'ENABLED',
    data.min_pin_length !== undefined ? Number(data.min_pin_length) : 6,
    data.max_pin_length !== undefined ? Number(data.max_pin_length) : 127,
    data.pin_uppercase || 'ALLOWED',
    data.pin_lowercase || 'ALLOWED',
    data.pin_special_chars || 'ALLOWED',
    data.pin_digits || 'REQUIRED',
    data.pin_expiration_days !== undefined ? Number(data.pin_expiration_days) : 0,
    data.pin_history_count !== undefined ? Number(data.pin_history_count) : 0,
    data.allow_biometrics !== undefined ? (data.allow_biometrics ? 1 : 0) : 1,
    data.require_enhanced_anti_spoofing !== undefined ? (data.require_enhanced_anti_spoofing ? 1 : 0) : 1,
    data.use_tpm_only !== undefined ? (data.use_tpm_only ? 1 : 0) : 1,
    data.allow_fido2_security_keys !== undefined ? (data.allow_fido2_security_keys ? 1 : 0) : 1,
    data.enabled !== undefined ? (data.enabled ? 1 : 0) : 1
  );

  return getWhfbPolicy(db, id);
}

/**
 * Update an existing WHfB policy
 */
export function updateWhfbPolicy(db, id, data) {
  const existing = getWhfbPolicy(db, id);
  if (!existing) return null;

  const fields = [];
  const params = [];

  const allowedCols = [
    'name', 'description', 'target_group_id', 'state',
    'min_pin_length', 'max_pin_length', 'pin_uppercase', 'pin_lowercase',
    'pin_special_chars', 'pin_digits', 'pin_expiration_days', 'pin_history_count',
    'allow_biometrics', 'require_enhanced_anti_spoofing', 'use_tpm_only',
    'allow_fido2_security_keys', 'enabled'
  ];

  for (const col of allowedCols) {
    if (data[col] !== undefined) {
      fields.push(`${col} = ?`);
      let val = data[col];
      if (['allow_biometrics', 'require_enhanced_anti_spoofing', 'use_tpm_only', 'allow_fido2_security_keys', 'enabled'].includes(col)) {
        val = val ? 1 : 0;
      }
      params.push(val);
    }
  }

  if (fields.length === 0) return existing;

  fields.push("updated_at = DATETIME('now')");
  params.push(id);

  db.prepare(`UPDATE whfb_policies SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  return getWhfbPolicy(db, id);
}

/**
 * Delete a WHfB policy
 */
export function deleteWhfbPolicy(db, id) {
  const existing = getWhfbPolicy(db, id);
  if (!existing) return false;
  db.prepare('DELETE FROM whfb_policies WHERE id = ?').run(id);
  return true;
}

/**
 * Generate a production PowerShell deployment script applying the policy to Windows Registry
 */
export function generateWhfbRegistryScript(policy) {
  if (!policy) return '# No policy provided';

  const isEnabled = policy.state === 'ENABLED' ? 1 : 0;
  const pinComplexityMap = {
    ALLOWED: 1,
    REQUIRED: 2,
    DISALLOWED: 3
  };

  return `# =====================================================================
# LocalPilot Windows Hello for Business & FIDO2 Enforcement Script
# Policy: ${policy.name} (${policy.id})
# State: ${policy.state} | Generated: ${new Date().toISOString()}
# =====================================================================

$ErrorActionPreference = 'Stop'
Write-Host "Applying Windows Hello for Business Policy [${policy.id}]..."

$passportKey = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork'
$pinKey      = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\PINComplexity'
$bioKey      = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\Biometrics'
$fidoKey     = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FIDO'

foreach ($k in @($passportKey, $pinKey, $bioKey, $fidoKey)) {
    if (-not (Test-Path $k)) {
        New-Item -Path $k -Force | Out-Null
    }
}

# 1. Base Passport for Work (WHfB) State
Set-ItemProperty -Path $passportKey -Name 'Enabled' -Type DWord -Value ${isEnabled}
Set-ItemProperty -Path $passportKey -Name 'DisablePostLogonProvisioning' -Type DWord -Value ${isEnabled ? 0 : 1}
Set-ItemProperty -Path $passportKey -Name 'RequireSecurityDevice' -Type DWord -Value ${policy.use_tpm_only ? 1 : 0}

# 2. PIN Complexity Requirements
Set-ItemProperty -Path $pinKey -Name 'MinimumPINLength' -Type DWord -Value ${policy.min_pin_length}
Set-ItemProperty -Path $pinKey -Name 'MaximumPINLength' -Type DWord -Value ${policy.max_pin_length}
Set-ItemProperty -Path $pinKey -Name 'UppercaseLetters' -Type DWord -Value ${pinComplexityMap[policy.pin_uppercase] || 1}
Set-ItemProperty -Path $pinKey -Name 'LowercaseLetters' -Type DWord -Value ${pinComplexityMap[policy.pin_lowercase] || 1}
Set-ItemProperty -Path $pinKey -Name 'SpecialCharacters' -Type DWord -Value ${pinComplexityMap[policy.pin_special_chars] || 1}
Set-ItemProperty -Path $pinKey -Name 'Digits' -Type DWord -Value ${pinComplexityMap[policy.pin_digits] || 2}
Set-ItemProperty -Path $pinKey -Name 'Expiration' -Type DWord -Value ${policy.pin_expiration_days}
Set-ItemProperty -Path $pinKey -Name 'History' -Type DWord -Value ${policy.pin_history_count}

# 3. Biometrics & Enhanced Anti-Spoofing
Set-ItemProperty -Path $bioKey -Name 'UseBiometrics' -Type DWord -Value ${policy.allow_biometrics ? 1 : 0}
Set-ItemProperty -Path $bioKey -Name 'FacialFeaturesUseEnhancedAntiSpoofing' -Type DWord -Value ${policy.require_enhanced_anti_spoofing ? 1 : 0}

# 4. FIDO2 / WebAuthn Security Key Logon
Set-ItemProperty -Path $fidoKey -Name 'EnableFIDODeviceLogon' -Type DWord -Value ${policy.allow_fido2_security_keys ? 1 : 0}

Write-Host "Windows Hello for Business policy enforced successfully."
`;
}

/**
 * Resolve effective WHfB policy for a device
 */
export function getEffectiveWhfbPolicyForDevice(db, deviceId) {
  // 1. Direct group membership priority match
  const match = db.prepare(`
    SELECT p.* 
    FROM whfb_policies p
    JOIN group_memberships gm ON p.target_group_id = gm.group_id
    JOIN dynamic_groups g ON gm.group_id = g.id
    WHERE gm.device_id = ? AND p.enabled = 1
    ORDER BY g.priority ASC, p.created_at ASC
    LIMIT 1
  `).get(deviceId);

  if (match) return match;

  // 2. Fallback to catch-all group or any enabled policy
  const fallback = db.prepare(`
    SELECT * FROM whfb_policies
    WHERE (target_group_id = 'grp-all' OR target_group_id IS NULL) AND enabled = 1
    ORDER BY created_at ASC
    LIMIT 1
  `).get();

  return fallback || null;
}

/**
 * Ingest / save device WHfB posture snapshot from agent heartbeat or audit
 */
export function saveDeviceWhfbStatus(db, deviceId, data) {
  const effectivePolicy = getEffectiveWhfbPolicyForDevice(db, deviceId);
  const policyId = data.policy_id || (effectivePolicy ? effectivePolicy.id : null);

  const existing = db.prepare('SELECT id FROM device_whfb_status WHERE device_id = ?').get(deviceId);
  const id = existing ? existing.id : `devwhfb-${deviceId}`;

  const whfbEnrolled = data.whfb_enrolled !== undefined ? (data.whfb_enrolled ? 1 : 0) : 0;
  const tpmPresent = data.tpm_present !== undefined ? (data.tpm_present ? 1 : 0) : 0;
  const tpmReady = data.tpm_ready !== undefined ? (data.tpm_ready ? 1 : 0) : 0;
  const biometricsAvailable = data.biometrics_available !== undefined ? (data.biometrics_available ? 1 : 0) : 0;
  const faceConfigured = data.face_auth_configured !== undefined ? (data.face_auth_configured ? 1 : 0) : 0;
  const fingerprintConfigured = data.fingerprint_auth_configured !== undefined ? (data.fingerprint_auth_configured ? 1 : 0) : 0;
  const pinComplexityCompliant = data.pin_complexity_compliant !== undefined ? (data.pin_complexity_compliant ? 1 : 0) : 1;
  const fido2KeysCount = data.fido2_keys_count !== undefined ? Number(data.fido2_keys_count) : 0;
  const antiSpoofingActive = data.anti_spoofing_active !== undefined ? (data.anti_spoofing_active ? 1 : 0) : 0;
  const provisioningState = data.whfb_provisioning_state || (whfbEnrolled ? 'ENROLLED' : 'NOT_ENROLLED');

  // Compute compliance
  let complianceStatus = 'COMPLIANT';
  if (effectivePolicy && effectivePolicy.state === 'ENABLED') {
    if (!whfbEnrolled) {
      complianceStatus = 'NOT_ENROLLED';
    } else if (effectivePolicy.use_tpm_only && (!tpmPresent || !tpmReady)) {
      complianceStatus = 'NON_COMPLIANT';
    } else if (!pinComplexityCompliant) {
      complianceStatus = 'NON_COMPLIANT';
    } else if (effectivePolicy.require_enhanced_anti_spoofing && (faceConfigured && !antiSpoofingActive)) {
      complianceStatus = 'NON_COMPLIANT';
    }
  }

  const lastAuditAt = data.last_audit_at || new Date().toISOString().replace('T', ' ').slice(0, 19);

  const stmt = db.prepare(`
    INSERT INTO device_whfb_status (
      id, device_id, policy_id, whfb_enrolled, whfb_provisioning_state,
      tpm_present, tpm_ready, biometrics_available, face_auth_configured,
      fingerprint_auth_configured, pin_complexity_compliant, fido2_keys_count,
      anti_spoofing_active, compliance_status, last_audit_at, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?,
      ?, ?, ?, DATETIME('now'), DATETIME('now')
    )
    ON CONFLICT(device_id) DO UPDATE SET
      policy_id = excluded.policy_id,
      whfb_enrolled = excluded.whfb_enrolled,
      whfb_provisioning_state = excluded.whfb_provisioning_state,
      tpm_present = excluded.tpm_present,
      tpm_ready = excluded.tpm_ready,
      biometrics_available = excluded.biometrics_available,
      face_auth_configured = excluded.face_auth_configured,
      fingerprint_auth_configured = excluded.fingerprint_auth_configured,
      pin_complexity_compliant = excluded.pin_complexity_compliant,
      fido2_keys_count = excluded.fido2_keys_count,
      anti_spoofing_active = excluded.anti_spoofing_active,
      compliance_status = excluded.compliance_status,
      last_audit_at = excluded.last_audit_at,
      updated_at = DATETIME('now')
  `);

  stmt.run(
    id, deviceId, policyId, whfbEnrolled, provisioningState,
    tpmPresent, tpmReady, biometricsAvailable, faceConfigured,
    fingerprintConfigured, pinComplexityCompliant, fido2KeysCount,
    antiSpoofingActive, complianceStatus, lastAuditAt
  );

  return db.prepare('SELECT * FROM device_whfb_status WHERE device_id = ?').get(deviceId);
}

/**
 * Record a WHfB / FIDO2 authentication or enrollment event in audit log
 */
export function recordWhfbEvent(db, deviceId, data) {
  const id = data.id || `whfbev-${randomUUID().slice(0, 8)}`;
  const eventType = data.event_type || 'AUTH_FAILURE';
  const credentialType = data.credential_type || 'PIN';
  const userName = data.user_name || '';
  const status = data.status || 'SUCCESS';
  const details = typeof data.details === 'object' ? JSON.stringify(data.details) : (data.details || '');
  const timestamp = data.timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19);

  db.prepare(`
    INSERT INTO whfb_audit_log (
      id, device_id, event_type, credential_type, user_name, status, details, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, deviceId, eventType, credentialType, userName, status, details, timestamp);

  // Escalate critical authentication failure or biometric spoof attempt to security_events
  if (status === 'BLOCKED' || eventType === 'SPOOF_ATTEMPT_BLOCKED' || (eventType === 'AUTH_FAILURE' && status === 'FAILURE')) {
    try {
      const dev = db.prepare('SELECT hostname FROM devices WHERE id = ?').get(deviceId);
      const hostname = dev ? dev.hostname : deviceId;
      const severity = eventType === 'SPOOF_ATTEMPT_BLOCKED' ? 'CRITICAL' : 'WARNING';
      const summary = eventType === 'SPOOF_ATTEMPT_BLOCKED'
        ? `Biometric spoofing attempt blocked by Enhanced Anti-Spoofing on ${hostname} (${userName})`
        : `Windows Hello authentication failure (${credentialType}) on ${hostname} for user ${userName}`;

      db.prepare(`
        INSERT INTO security_events (
          device_id, event_type, severity, summary, event_source, raw_payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, DATETIME('now'))
      `).run(
        deviceId,
        'POLICY_DRIFT',
        severity,
        summary,
        'WHFB_SUBSYSTEM',
        JSON.stringify({ event_type: eventType, credential_type: credentialType, user: userName, details, ...data })
      );
    } catch (e) {
      console.error('[whfbEngine] Failed to write security event:', e.message);
    }
  }

  return db.prepare('SELECT * FROM whfb_audit_log WHERE id = ?').get(id);
}

/**
 * Get fleet-wide WHfB inventory
 */
export function getWhfbInventory(db, filter = {}) {
  let query = `
    SELECT s.*, d.hostname, d.friendly_name, d.ip_address as device_ip, d.status as device_status,
           p.name as policy_name, p.state as policy_state, p.min_pin_length, p.use_tpm_only
    FROM device_whfb_status s
    JOIN devices d ON s.device_id = d.id
    LEFT JOIN whfb_policies p ON s.policy_id = p.id
    WHERE 1=1
  `;
  const params = [];

  if (filter.compliance_status) {
    query += ' AND s.compliance_status = ?';
    params.push(filter.compliance_status);
  }
  if (filter.whfb_enrolled !== undefined) {
    query += ' AND s.whfb_enrolled = ?';
    params.push(filter.whfb_enrolled ? 1 : 0);
  }

  query += ' ORDER BY s.updated_at DESC';
  return db.prepare(query).all(...params);
}

/**
 * Get historical WHfB audit events
 */
export function getWhfbAuditLog(db, limit = 100) {
  return db.prepare(`
    SELECT l.*, d.hostname
    FROM whfb_audit_log l
    JOIN devices d ON l.device_id = d.id
    ORDER BY l.timestamp DESC
    LIMIT ?
  `).all(limit);
}

/**
 * Get executive summary statistics for WHfB & FIDO2
 */
export function getWhfbStats(db) {
  const polRow = db.prepare(`
    SELECT 
      COUNT(*) as total_policies,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as active_policies
    FROM whfb_policies
  `).get();

  const devRow = db.prepare(`
    SELECT 
      COUNT(*) as total_audited,
      SUM(CASE WHEN whfb_enrolled = 1 THEN 1 ELSE 0 END) as enrolled_count,
      SUM(CASE WHEN tpm_present = 1 AND tpm_ready = 1 THEN 1 ELSE 0 END) as tpm_attested_count,
      SUM(CASE WHEN face_auth_configured = 1 OR fingerprint_auth_configured = 1 THEN 1 ELSE 0 END) as biometrics_active_count,
      SUM(CASE WHEN fido2_keys_count > 0 THEN 1 ELSE 0 END) as fido2_active_count,
      SUM(CASE WHEN compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant_count
    FROM device_whfb_status
  `).get();

  const totalDevices = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
  const totalAuditEvents = db.prepare('SELECT COUNT(*) as c FROM whfb_audit_log').get().c;

  const auditedCount = devRow.total_audited || 0;
  const enrolledCount = devRow.enrolled_count || 0;
  const compliantCount = devRow.compliant_count || 0;

  const enrolledPct = auditedCount > 0 ? Math.round((enrolledCount / auditedCount) * 100) : 0;
  const compliancePct = auditedCount > 0 ? Math.round((compliantCount / auditedCount) * 100) : 100;

  return {
    total_policies: polRow.total_policies || 0,
    active_policies: polRow.active_policies || 0,
    total_audited_devices: auditedCount,
    total_devices_in_fleet: totalDevices,
    enrolled_devices_count: enrolledCount,
    enrolled_pct: enrolledPct,
    tpm_attested_devices_count: devRow.tpm_attested_count || 0,
    biometrics_active_count: devRow.biometrics_active_count || 0,
    fido2_active_count: devRow.fido2_active_count || 0,
    compliant_devices_count: compliantCount,
    compliance_pct: compliancePct,
    total_audit_events: totalAuditEvents
  };
}

/**
 * Get device-specific WHfB status, policy, and audit log
 */
export function getDeviceWhfbStatus(db, deviceId) {
  const status = db.prepare(`
    SELECT s.*, p.name as policy_name, p.state as policy_state, p.min_pin_length,
           p.allow_biometrics, p.require_enhanced_anti_spoofing, p.use_tpm_only, p.allow_fido2_security_keys
    FROM device_whfb_status s
    LEFT JOIN whfb_policies p ON s.policy_id = p.id
    WHERE s.device_id = ?
  `).get(deviceId);

  const effectivePolicy = getEffectiveWhfbPolicyForDevice(db, deviceId);
  const recentEvents = db.prepare(`
    SELECT * FROM whfb_audit_log
    WHERE device_id = ?
    ORDER BY timestamp DESC
    LIMIT 20
  `).all(deviceId);

  return {
    status: status || null,
    effective_policy: effectivePolicy || null,
    recent_events: recentEvents || []
  };
}
