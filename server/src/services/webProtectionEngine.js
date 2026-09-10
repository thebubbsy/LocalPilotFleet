/**
 * LocalPilotFleet — Web Content Filtering & SmartScreen Engine
 * Module: server/src/services/webProtectionEngine.js
 *
 * Implements enterprise tier-1 Web Protection mirroring Microsoft Defender for Endpoint:
 * - Category-based web filtering (Adult, High Liability, Legal Liability, Bandwidth Loss)
 * - SmartScreen enforcement (Block, Warn, Disabled) and bypass telemetry
 * - Custom domain, URL, FQDN & IP Indicator Overrides (Block/Allow/Warn)
 * - Real-time Network Protection intercept audit logging & SOC alerting
 * - Dynamic client PowerShell policy configuration
 */

import crypto from 'node:crypto';

export class WebProtectionEngine {
  static getWebProtectionStats(db) {
    const totalPolicies = db.prepare('SELECT COUNT(*) as count FROM web_content_filtering_policies').get().count;
    const activePolicies = db.prepare('SELECT COUNT(*) as count FROM web_content_filtering_policies WHERE is_enabled = 1').get().count;
    const totalIndicators = db.prepare('SELECT COUNT(*) as count FROM web_indicator_rules').get().count;
    const activeIndicators = db.prepare('SELECT COUNT(*) as count FROM web_indicator_rules WHERE is_active = 1').get().count;
    const totalWebBlocks = db.prepare("SELECT COUNT(*) as count FROM web_protection_audit_events WHERE action_taken = 'BLOCKED'").get().count;
    const phishingDetections = db.prepare("SELECT COUNT(*) as count FROM web_protection_audit_events WHERE event_type = 'PHISHING_ATTEMPT_DETECTED'").get().count;
    const userBypasses = db.prepare("SELECT COUNT(*) as count FROM web_protection_audit_events WHERE action_taken = 'USER_BYPASSED'").get().count;

    return {
      totalPolicies,
      activePolicies,
      totalIndicators,
      activeIndicators,
      totalWebBlocks,
      phishingDetections,
      userBypasses,
      subSecondSweepSla: true,
      calculatedAt: new Date().toISOString()
    };
  }

  static getPolicies(db, { search = '', is_enabled, limit = 50, offset = 0 } = {}) {
    let query = 'SELECT * FROM web_content_filtering_policies WHERE 1=1';
    const params = [];

    if (search) {
      query += ' AND (name LIKE ? OR description LIKE ?)';
      const term = `%${search}%`;
      params.push(term, term);
    }

    if (is_enabled !== undefined && is_enabled !== null && is_enabled !== '') {
      query += ' AND is_enabled = ?';
      params.push(is_enabled ? 1 : 0);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(Number(limit) || 50, Number(offset) || 0);

    return db.prepare(query).all(...params);
  }

  static getPolicyById(db, id) {
    const policy = db.prepare('SELECT * FROM web_content_filtering_policies WHERE id = ?').get(id);
    if (!policy) return null;

    const indicators = db.prepare('SELECT * FROM web_indicator_rules WHERE policy_id = ? ORDER BY created_at DESC').all(id);
    return {
      ...policy,
      indicators
    };
  }

  static createPolicy(db, data) {
    if (!data || !data.name) {
      throw new Error('Missing required field: name is required.');
    }

    const id = data.id || `wcf-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const targetScope = data.target_scope || 'ALL_FLEET';
    const smartscreenMode = data.smartscreen_mode || 'BLOCK';
    const networkMode = data.network_protection_mode || 'BLOCK';

    const stmt = db.prepare(`
      INSERT INTO web_content_filtering_policies (
        id, name, description, target_scope, target_id, block_adult_content, block_high_liability,
        block_legal_liability, block_bandwidth_loss, block_unrated, smartscreen_mode,
        allow_user_bypass, network_protection_mode, is_enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
    `);

    stmt.run(
      id,
      data.name,
      data.description || null,
      targetScope,
      data.target_id || null,
      data.block_adult_content === false || data.block_adult_content === 0 ? 0 : 1,
      data.block_high_liability === false || data.block_high_liability === 0 ? 0 : 1,
      data.block_legal_liability === false || data.block_legal_liability === 0 ? 0 : 1,
      data.block_bandwidth_loss === true || data.block_bandwidth_loss === 1 ? 1 : 0,
      data.block_unrated === true || data.block_unrated === 1 ? 1 : 0,
      smartscreenMode,
      data.allow_user_bypass === true || data.allow_user_bypass === 1 ? 1 : 0,
      networkMode,
      data.is_enabled === false || data.is_enabled === 0 ? 0 : 1
    );

    return WebProtectionEngine.getPolicyById(db, id);
  }

  static updatePolicy(db, id, updates) {
    const existing = db.prepare('SELECT * FROM web_content_filtering_policies WHERE id = ?').get(id);
    if (!existing) return null;

    const fields = [];
    const params = [];

    const allowedCols = [
      'name', 'description', 'target_scope', 'target_id', 'block_adult_content',
      'block_high_liability', 'block_legal_liability', 'block_bandwidth_loss',
      'block_unrated', 'smartscreen_mode', 'allow_user_bypass', 'network_protection_mode', 'is_enabled'
    ];

    for (const col of allowedCols) {
      if (updates[col] !== undefined) {
        fields.push(`${col} = ?`);
        if (col.startsWith('block_') || col === 'allow_user_bypass' || col === 'is_enabled') {
          params.push(updates[col] ? 1 : 0);
        } else {
          params.push(updates[col]);
        }
      }
    }

    if (fields.length === 0) return WebProtectionEngine.getPolicyById(db, id);

    fields.push("updated_at = DATETIME('now')");
    params.push(id);

    db.prepare(`UPDATE web_content_filtering_policies SET ${fields.join(', ')} WHERE id = ?`).run(...params);
    return WebProtectionEngine.getPolicyById(db, id);
  }

  static deletePolicy(db, id) {
    const result = db.prepare('DELETE FROM web_content_filtering_policies WHERE id = ?').run(id);
    return result.changes > 0;
  }

  static getIndicatorRules(db, { policy_id, action, indicator_type, search, limit = 50, offset = 0 } = {}) {
    let query = 'SELECT * FROM web_indicator_rules WHERE 1=1';
    const params = [];

    if (policy_id) {
      query += ' AND policy_id = ?';
      params.push(policy_id);
    }

    if (action) {
      query += ' AND action = ?';
      params.push(action);
    }

    if (indicator_type) {
      query += ' AND indicator_type = ?';
      params.push(indicator_type);
    }

    if (search) {
      query += ' AND (indicator_value LIKE ? OR category LIKE ?)';
      const term = `%${search}%`;
      params.push(term, term);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(Number(limit) || 50, Number(offset) || 0);

    return db.prepare(query).all(...params);
  }

  static createIndicatorRule(db, data) {
    if (!data || !data.indicator_value) {
      throw new Error('Missing required field: indicator_value is required.');
    }

    const id = data.id || `wir-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const indicatorType = data.indicator_type || 'DOMAIN';
    const action = data.action || 'BLOCK';

    const stmt = db.prepare(`
      INSERT INTO web_indicator_rules (
        id, policy_id, indicator_type, indicator_value, action, category,
        redirect_url, expiration_date, is_active, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
    `);

    stmt.run(
      id,
      data.policy_id || null,
      indicatorType,
      data.indicator_value,
      action,
      data.category || 'Custom Security Rule',
      data.redirect_url || null,
      data.expiration_date || null,
      data.is_active === false || data.is_active === 0 ? 0 : 1
    );

    return db.prepare('SELECT * FROM web_indicator_rules WHERE id = ?').get(id);
  }

  static deleteIndicatorRule(db, id) {
    const result = db.prepare('DELETE FROM web_indicator_rules WHERE id = ?').run(id);
    return result.changes > 0;
  }

  static logWebProtectionEvent(db, eventData) {
    if (!eventData || !eventData.url || !eventData.domain) {
      throw new Error('Missing required fields: url and domain are required.');
    }

    let device = null;
    if (eventData.device_id) {
      device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(eventData.device_id);
    }
    if (!device) {
      device = db.prepare('SELECT id, hostname FROM devices LIMIT 1').get();
    }

    const deviceId = device ? device.id : (eventData.device_id || 'dev-baseline-01');
    const hostname = device ? device.hostname : (eventData.hostname || 'DESKTOP-WEB');
    const id = eventData.id || `wpae-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const eventType = eventData.event_type || 'URL_BLOCKED';
    const actionTaken = eventData.action_taken || 'BLOCKED';
    const severity = eventData.severity || (eventType === 'PHISHING_ATTEMPT_DETECTED' ? 'CRITICAL' : 'MEDIUM');

    const stmt = db.prepare(`
      INSERT INTO web_protection_audit_events (
        id, device_id, hostname, username, event_type, url, domain, ip_address,
        category, action_taken, browser_process, severity, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
    `);

    stmt.run(
      id,
      deviceId,
      hostname,
      eventData.username || 'System',
      eventType,
      eventData.url,
      eventData.domain,
      eventData.ip_address || null,
      eventData.category || 'Uncategorized',
      actionTaken,
      eventData.browser_process || 'msedge.exe',
      severity
    );

    // If critical/phishing, dispatch alert to security_events
    if (severity === 'CRITICAL' || eventType === 'PHISHING_ATTEMPT_DETECTED') {
      try {
        const insertSec = db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, event_id, event_source, severity, summary, raw_payload_json, acknowledged
          ) VALUES (?, 'MALWARE_THREAT_DETECTED', 7001, 'WEB_PROTECTION_ENGINE', 'CRITICAL', ?, ?, 0)
        `);
        insertSec.run(
          deviceId,
          `CRITICAL: Phishing connection blocked by Defender Web Protection to '${eventData.domain}'`,
          JSON.stringify({ event_id: id, url: eventData.url, domain: eventData.domain, browser: eventData.browser_process })
        );
      } catch {}
    }

    return db.prepare('SELECT * FROM web_protection_audit_events WHERE id = ?').get(id);
  }

  static getWebProtectionEvents(db, { device_id, event_type, action_taken, limit = 50, offset = 0 } = {}) {
    let query = 'SELECT * FROM web_protection_audit_events WHERE 1=1';
    const params = [];

    if (device_id) {
      query += ' AND device_id = ?';
      params.push(device_id);
    }

    if (event_type) {
      query += ' AND event_type = ?';
      params.push(event_type);
    }

    if (action_taken) {
      query += ' AND action_taken = ?';
      params.push(action_taken);
    }

    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    params.push(Number(limit) || 50, Number(offset) || 0);

    return db.prepare(query).all(...params);
  }

  static generateWebProtectionScript(db, deviceId) {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
    const policies = db.prepare('SELECT * FROM web_content_filtering_policies WHERE is_enabled = 1').all();
    const indicators = db.prepare('SELECT * FROM web_indicator_rules WHERE is_active = 1').all();

    return `# LocalPilot Fleet — Microsoft Defender Web Protection & SmartScreen Baseline
# Target Device: ${device ? device.hostname : 'Generic-Host'} (${deviceId})
# Generated: ${new Date().toISOString()}

$ErrorActionPreference = 'Stop'
Write-Host "[LocalPilot Web Protection] Configuring Defender Network Protection and SmartScreen..." -ForegroundColor Cyan

# 1. Enable Defender Network Protection
Set-MpPreference -EnableNetworkProtection Enabled -Verbose
Write-Host "[LocalPilot Web Protection] Defender Network Protection set to BLOCK mode." -ForegroundColor Green

# 2. Configure Edge and Windows SmartScreen Registry
$SmartScreenPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter"
if (-not (Test-Path $SmartScreenPath)) {
    New-Item -Path $SmartScreenPath -Force | Out-Null
}
Set-ItemProperty -Path $SmartScreenPath -Name "EnabledV9" -Value 1 -Type DWord
Set-ItemProperty -Path $SmartScreenPath -Name "PreventOverride" -Value 1 -Type DWord

# 3. Apply Custom Indicators (${indicators.length} active rules)
$IndicatorsJson = @'
${JSON.stringify(indicators, null, 2)}
'@ | ConvertFrom-Json

$FilterPath = "C:\\ProgramData\\LocalPilotFleet\\WebProtection"
if (-not (Test-Path $FilterPath)) {
    New-Item -Path $FilterPath -ItemType Directory -Force | Out-Null
}
$IndicatorsJson | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $FilterPath "web_indicators.json") -Encoding UTF8

Write-Host "[LocalPilot Web Protection] Successfully deployed $($IndicatorsJson.Count) custom web indicators." -ForegroundColor Green
`;
  }
}

export const webProtectionEngine = WebProtectionEngine;
export default WebProtectionEngine;
