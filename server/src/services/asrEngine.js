/**
 * LocalPilot Fleet — Microsoft Intune Endpoint Security > Attack Surface Reduction Engine
 * server/src/services/asrEngine.js
 */

const ASR_RULE_NAMES = {
  'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': 'Block executable content from email client and webmail',
  '3b576869-a4ec-4529-8536-b80a7769e899': 'Block Office apps from creating executable content',
  '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84': 'Block Office apps from injecting code into other processes',
  'd4f940ab-401b-4efc-aadc-ad5f3c50688a': 'Block Office apps from creating child processes',
  '26190899-1602-49e8-8b27-eb1d0a1ce869': 'Block Win32 API calls from Office macros',
  'e6db77e5-3df2-4cf1-b95a-636979351e5b': 'Block persistence through WMI event subscription',
  'd3e037e1-3eb8-44c8-a917-57927947596d': 'Block JavaScript or VBScript from launching downloaded executable content',
  '5beb7efe-fd9a-4556-801d-275e5ffc04cc': 'Block execution of potentially obfuscated scripts',
  '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b': 'Block Win32 imports from Macro code in Office',
  '01443614-cd74-433a-b99e-2ecdc07bfc25': 'Block executable files from running unless they meet a prevalence criterion',
  'c1db55ab-c21a-4637-bb3f-a12568109d35': 'Use advanced protection against ransomware',
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0': 'Block credential stealing from Windows LSASS',
  'd1e49aac-8f56-4280-b9ba-993a6d77406c': 'Block process creations originating from PSExec and WMI commands',
  'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': 'Block untrusted and unsigned processes from USB',
  'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb': 'Block Adobe Reader from creating child processes',
  '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c': 'Block Office communication apps from creating child processes'
};

const VALID_MODES = ['DISABLED', 'AUDIT', 'BLOCK'];
const VALID_NP_MODES = ['DISABLED', 'AUDIT', 'BLOCK'];
const VALID_CFA_MODES = ['DISABLED', 'AUDIT', 'BLOCK', 'BLOCK_DISK_MOD_ONLY', 'AUDIT_DISK_MOD_ONLY'];

function genId(prefix = 'asr') {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
}

function safeJson(str) {
  try { return JSON.parse(str || '{}'); } catch { return {}; }
}

function countBlockModeRules(db) {
  const policies = db.prepare('SELECT asr_rules_json FROM asr_policies WHERE enabled = 1').all();
  let blockCount = 0;
  for (const pol of policies) {
    try {
      const rules = JSON.parse(pol.asr_rules_json || '{}');
      blockCount += Object.values(rules).filter(v => v === 'BLOCK').length;
    } catch {}
  }
  return blockCount;
}

export function getASRPolicyStats(db) {
  const totalPolicies = db.prepare('SELECT COUNT(*) as c FROM asr_policies').get().c;
  const blockModeCount = countBlockModeRules(db);
  const eventsToday = db.prepare(`
    SELECT COUNT(*) as c FROM asr_events
    WHERE occurred_at >= DATETIME('now', '-1 day')
       OR created_at >= DATETIME('now', '-1 day')
  `).get().c;
  const devicesCovered = db.prepare('SELECT COUNT(DISTINCT device_id) as c FROM device_asr_status').get().c;
  const pols = db.prepare('SELECT asr_rules_json FROM asr_policies WHERE enabled = 1').all();
  let auditModeCount = 0;
  for (const pol of pols) {
    try { const rules = JSON.parse(pol.asr_rules_json || '{}'); auditModeCount += Object.values(rules).filter(v => v === 'AUDIT').length; } catch {}
  }
  return { total_policies: totalPolicies, block_mode_count: blockModeCount, audit_mode_count: auditModeCount, events_today: eventsToday, devices_covered: devicesCovered };
}

export function getASRPolicies(db, filters = {}) {
  const { target_group_id, enabled } = filters;
  let sql = `SELECT ap.*, dg.name as target_group_name FROM asr_policies ap LEFT JOIN dynamic_groups dg ON ap.target_group_id = dg.id WHERE 1=1`;
  const params = [];
  if (target_group_id) { sql += ' AND ap.target_group_id = ?'; params.push(target_group_id); }
  if (enabled !== undefined && enabled !== '') { sql += ' AND ap.enabled = ?'; params.push(enabled === 'true' || enabled === 1 || enabled === '1' ? 1 : 0); }
  sql += ' ORDER BY ap.created_at DESC';
  const rows = db.prepare(sql).all(...params);
  return rows.map(r => ({ ...r, enabled: Boolean(r.enabled), asr_rules: safeJson(r.asr_rules_json), exploit_protection: safeJson(r.exploit_protection_json) }));
}

export function getASRPolicy(db, id) {
  const row = db.prepare(`SELECT ap.*, dg.name as target_group_name FROM asr_policies ap LEFT JOIN dynamic_groups dg ON ap.target_group_id = dg.id WHERE ap.id = ?`).get(id);
  if (!row) return null;
  const eventCount = db.prepare(`SELECT COUNT(*) as c FROM asr_events WHERE device_id IN (SELECT device_id FROM device_asr_status WHERE policy_id = ?) AND (occurred_at >= DATETIME('now', '-7 days') OR created_at >= DATETIME('now', '-7 days'))`).get(id).c;
  return { ...row, enabled: Boolean(row.enabled), asr_rules: safeJson(row.asr_rules_json), exploit_protection: safeJson(row.exploit_protection_json), recent_event_count: eventCount };
}

export function createASRPolicy(db, payload) {
  const { name, description = '', target_group_id = 'grp-all', enabled = 1, asr_rules = {}, exploit_protection = {}, network_protection_mode = 'AUDIT', controlled_folder_access = 'DISABLED' } = payload;
  if (!name || !String(name).trim()) throw new Error('Policy name is required');
  if (!VALID_NP_MODES.includes(network_protection_mode)) throw new Error(`network_protection_mode must be one of: ${VALID_NP_MODES.join(', ')}`);
  if (!VALID_CFA_MODES.includes(controlled_folder_access)) throw new Error(`controlled_folder_access must be one of: ${VALID_CFA_MODES.join(', ')}`);
  for (const [ruleId, mode] of Object.entries(asr_rules)) {
    if (!VALID_MODES.includes(mode)) throw new Error(`Invalid mode '${mode}' for rule ${ruleId}. Must be one of: ${VALID_MODES.join(', ')}`);
  }
  const id = payload.id && String(payload.id).trim() ? String(payload.id).trim() : genId('asr-pol');
  db.prepare(`INSERT INTO asr_policies (id, name, description, target_group_id, enabled, asr_rules_json, exploit_protection_json, network_protection_mode, controlled_folder_access, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))`).run(id, String(name).trim(), String(description).trim(), target_group_id || 'grp-all', enabled ? 1 : 0, JSON.stringify(asr_rules), JSON.stringify(exploit_protection), network_protection_mode, controlled_folder_access);
  return getASRPolicy(db, id);
}

export function updateASRPolicy(db, id, updates) {
  const existing = getASRPolicy(db, id);
  if (!existing) throw new Error(`ASR policy not found: ${id}`);
  const fields = []; const params = [];
  if (updates.name !== undefined) { if (!String(updates.name).trim()) throw new Error('Policy name cannot be empty'); fields.push('name = ?'); params.push(String(updates.name).trim()); }
  if (updates.description !== undefined) { fields.push('description = ?'); params.push(String(updates.description).trim()); }
  if (updates.target_group_id !== undefined) { fields.push('target_group_id = ?'); params.push(updates.target_group_id || 'grp-all'); }
  if (updates.enabled !== undefined) { fields.push('enabled = ?'); params.push(updates.enabled ? 1 : 0); }
  if (updates.asr_rules !== undefined) {
    for (const [ruleId, mode] of Object.entries(updates.asr_rules)) {
      if (!VALID_MODES.includes(mode)) throw new Error(`Invalid mode '${mode}' for rule ${ruleId}`);
    }
    fields.push('asr_rules_json = ?'); params.push(JSON.stringify(updates.asr_rules));
  }
  if (updates.exploit_protection !== undefined) { fields.push('exploit_protection_json = ?'); params.push(JSON.stringify(updates.exploit_protection)); }
  if (updates.network_protection_mode !== undefined) { if (!VALID_NP_MODES.includes(updates.network_protection_mode)) throw new Error(`network_protection_mode must be one of: ${VALID_NP_MODES.join(', ')}`); fields.push('network_protection_mode = ?'); params.push(updates.network_protection_mode); }
  if (updates.controlled_folder_access !== undefined) { if (!VALID_CFA_MODES.includes(updates.controlled_folder_access)) throw new Error(`controlled_folder_access must be one of: ${VALID_CFA_MODES.join(', ')}`); fields.push('controlled_folder_access = ?'); params.push(updates.controlled_folder_access); }
  if (!fields.length) return existing;
  fields.push("updated_at = DATETIME('now')"); params.push(id);
  db.prepare(`UPDATE asr_policies SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  return getASRPolicy(db, id);
}

export function deleteASRPolicy(db, id) {
  const existing = getASRPolicy(db, id);
  if (!existing) throw new Error(`ASR policy not found: ${id}`);
  db.prepare('DELETE FROM asr_policies WHERE id = ?').run(id);
  return { success: true, id };
}

export function getASREvents(db, filters = {}) {
  const { device_id, rule_id, action, limit = 100, offset = 0 } = filters;
  let sql = `SELECT ae.*, d.hostname, d.friendly_name FROM asr_events ae LEFT JOIN devices d ON ae.device_id = d.id WHERE 1=1`;
  const params = [];
  if (device_id) { sql += ' AND ae.device_id = ?'; params.push(device_id); }
  if (rule_id) { sql += ' AND ae.rule_id = ?'; params.push(rule_id); }
  if (action) { sql += ' AND ae.action = ?'; params.push(action); }
  const countSql = sql.replace('ae.*, d.hostname, d.friendly_name', 'COUNT(*) as c');
  const count = db.prepare(countSql).get(...params).c;
  sql += ' ORDER BY COALESCE(ae.occurred_at, ae.created_at) DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));
  const events = db.prepare(sql).all(...params);
  return { events, count };
}

export function getDeviceASRStatus(db, deviceId) {
  const status = db.prepare(`SELECT das.*, ap.name as policy_name FROM device_asr_status das LEFT JOIN asr_policies ap ON das.policy_id = ap.id WHERE das.device_id = ? ORDER BY das.updated_at DESC LIMIT 1`).get(deviceId);
  const recentEvents = db.prepare(`SELECT * FROM asr_events WHERE device_id = ? ORDER BY COALESCE(occurred_at, created_at) DESC LIMIT 20`).all(deviceId);
  const eventsToday = db.prepare(`SELECT COUNT(*) as c FROM asr_events WHERE device_id = ? AND (occurred_at >= DATETIME('now', '-1 day') OR created_at >= DATETIME('now', '-1 day'))`).get(deviceId).c;
  return { device_id: deviceId, status: status ? { ...status, exploit_protection_applied: Boolean(status.exploit_protection_applied), asr_rules_status: safeJson(status.asr_rules_status_json) } : null, recent_events: recentEvents, events_today: eventsToday };
}

export function saveDeviceASRStatus(db, payload) {
  const { deviceId, policyId, asrRulesStatus = {}, networkProtectionMode = 'UNKNOWN', controlledFolderAccess = 'UNKNOWN', exploitProtectionApplied = false } = payload;
  if (!deviceId) throw new Error('deviceId is required');
  const existing = db.prepare('SELECT id FROM device_asr_status WHERE device_id = ?').get(deviceId);
  if (existing) {
    db.prepare(`UPDATE device_asr_status SET policy_id = ?, asr_rules_status_json = ?, network_protection_mode = ?, controlled_folder_access = ?, exploit_protection_applied = ?, last_audited_at = DATETIME('now'), updated_at = DATETIME('now') WHERE device_id = ?`).run(policyId || null, JSON.stringify(asrRulesStatus), networkProtectionMode, controlledFolderAccess, exploitProtectionApplied ? 1 : 0, deviceId);
    return db.prepare('SELECT * FROM device_asr_status WHERE device_id = ?').get(deviceId);
  } else {
    const id = genId('das');
    db.prepare(`INSERT INTO device_asr_status (id, device_id, policy_id, asr_rules_status_json, network_protection_mode, controlled_folder_access, exploit_protection_applied, last_audited_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'), DATETIME('now'))`).run(id, deviceId, policyId || null, JSON.stringify(asrRulesStatus), networkProtectionMode, controlledFolderAccess, exploitProtectionApplied ? 1 : 0);
    return db.prepare('SELECT * FROM device_asr_status WHERE id = ?').get(id);
  }
}

export function saveASREvents(db, deviceId, events) {
  if (!deviceId) throw new Error('deviceId is required');
  if (!Array.isArray(events)) throw new Error('events must be an array');
  const insert = db.prepare(`INSERT OR IGNORE INTO asr_events (id, device_id, event_id, rule_id, rule_name, action, process_name, target_path, initiating_process, event_source, occurred_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))`);
  const saved = [];
  db.exec('BEGIN');
  try {
    for (const evt of events) {
      const action = evt.action;
      if (!['BLOCKED','AUDITED','NETWORK_BLOCKED','NETWORK_AUDITED'].includes(action)) continue;
      const id = genId('asre');
      const ruleId = evt.rule_id || null;
      const ruleName = ruleId ? (ASR_RULE_NAMES[ruleId.toLowerCase()] || evt.rule_name || null) : (evt.rule_name || null);
      const eventId = action === 'BLOCKED' ? 1121 : action === 'AUDITED' ? 1122 : action === 'NETWORK_BLOCKED' ? 1125 : 1126;
      insert.run(id, deviceId, evt.event_id || eventId, ruleId, ruleName, action, evt.process_name || null, evt.target_path || null, evt.initiating_process || null, evt.event_source || 'Microsoft-Windows-Windows Defender', evt.occurred_at || null);
      saved.push(id);
    }
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch {}
    throw err;
  }
  return saved;
}

export function getAssignedASRPolicyForDevice(db, deviceId) {
  try {
    const groupRows = db.prepare('SELECT group_id FROM group_memberships WHERE device_id = ?').all(deviceId);
    const groupIds = new Set(groupRows.map(r => r.group_id));
    groupIds.add('grp-all');
    const allPolicies = db.prepare(`SELECT ap.*, dg.name as target_group_name FROM asr_policies ap LEFT JOIN dynamic_groups dg ON ap.target_group_id = dg.id WHERE ap.enabled = 1 ORDER BY ap.created_at ASC`).all();
    let assigned = null;
    for (const pol of allPolicies) {
      if (!pol.target_group_id || groupIds.has(pol.target_group_id)) {
        if (!assigned || pol.target_group_id !== 'grp-all') assigned = pol;
      }
    }
    if (!assigned) return null;
    return { ...assigned, enabled: Boolean(assigned.enabled), asr_rules: safeJson(assigned.asr_rules_json), exploit_protection: safeJson(assigned.exploit_protection_json) };
  } catch { return null; }
}
