import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';

// Default pre-shared key matching architecture spec
export const DEFAULT_FLEET_KEY = 'LP-FleetKey-984f48b8-6a3c-4e7a-9a99-4c6ec083b7f1';

/**
 * Initializes SQLite database with the authoritative 8-table schema and seeds
 */
export function initDatabase(dbPath = ':memory:') {
  const db = new DatabaseSync(dbPath);

  // WAL and concurrency pragmas (ignored or benign in memory mode)
  try {
    db.exec('PRAGMA foreign_keys = ON;');
    db.exec('PRAGMA busy_timeout = 5000;');
  } catch {
    // Ignore in-memory pragma errors if any
  }

  // Schema creation: 8 tables per architecture specification
  db.exec(`
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY NOT NULL,
      hostname TEXT NOT NULL,
      friendly_name TEXT,
      serial_number TEXT UNIQUE,
      uuid TEXT UNIQUE,
      mac_address TEXT,
      ip_address TEXT,
      public_ip TEXT,
      connection_route TEXT DEFAULT 'LAN' CHECK(connection_route IN ('LAN', 'Cloudflare', 'Unknown')),
      status TEXT DEFAULT 'online' CHECK(status IN ('online', 'offline', 'drifted', 'quarantined')),
      os_name TEXT NOT NULL,
      os_version TEXT NOT NULL,
      os_build TEXT,
      os_architecture TEXT DEFAULT '64-bit',
      cpu_model TEXT,
      cpu_cores INTEGER,
      cpu_logical INTEGER,
      total_ram_bytes INTEGER NOT NULL,
      total_ram_gb REAL GENERATED ALWAYS AS (ROUND(total_ram_bytes / 1073741824.0, 2)) STORED,
      gpu_name TEXT,
      has_battery INTEGER DEFAULT 0 CHECK(has_battery IN (0, 1)),
      battery_percent REAL,
      battery_charging INTEGER DEFAULT 0 CHECK(battery_charging IN (0, 1)),
      tpm_present INTEGER DEFAULT 0 CHECK(tpm_present IN (0, 1)),
      tpm_version TEXT,
      tpm_enabled INTEGER DEFAULT 0 CHECK(tpm_enabled IN (0, 1)),
      secure_boot_enabled INTEGER DEFAULT 0 CHECK(secure_boot_enabled IN (0, 1)),
      bitlocker_status TEXT DEFAULT 'Disabled' CHECK(bitlocker_status IN ('FullyEncrypted', 'FullyDecrypted', 'EncryptionInProgress', 'Disabled')),
      primary_user TEXT,
      tags_json TEXT DEFAULT '[]',
      assigned_group TEXT,
      node_token_hash TEXT NOT NULL,
      agent_version TEXT NOT NULL,
      enrolled_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      last_seen_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );

    CREATE TABLE IF NOT EXISTS telemetry_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      timestamp TEXT NOT NULL DEFAULT (DATETIME('now')),
      cpu_usage_percent REAL NOT NULL,
      ram_used_bytes INTEGER NOT NULL,
      ram_free_bytes INTEGER NOT NULL,
      ram_usage_percent REAL NOT NULL,
      disk_free_gb REAL,
      disks_json TEXT NOT NULL,
      network_json TEXT,
      battery_percent REAL,
      battery_charging INTEGER DEFAULT 0,
      process_count INTEGER,
      uptime_seconds INTEGER,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS dynamic_groups (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      rule_syntax TEXT NOT NULL,
      is_dynamic INTEGER DEFAULT 1 CHECK(is_dynamic IN (0, 1)),
      color TEXT DEFAULT '#3B82F6',
      icon TEXT DEFAULT 'laptop',
      priority INTEGER DEFAULT 100,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );

    CREATE TABLE IF NOT EXISTS group_memberships (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      is_dynamic_match INTEGER DEFAULT 1 CHECK(is_dynamic_match IN (0, 1)),
      manually_assigned INTEGER DEFAULT 0 CHECK(manually_assigned IN (0, 1)),
      evaluated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(group_id) REFERENCES dynamic_groups(id) ON DELETE CASCADE,
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
      UNIQUE(group_id, device_id)
    );

    CREATE TABLE IF NOT EXISTS software_catalog (
      id TEXT PRIMARY KEY NOT NULL,
      name TEXT NOT NULL,
      publisher TEXT,
      winget_id TEXT NOT NULL UNIQUE,
      version TEXT,
      category TEXT DEFAULT 'Utilities',
      description TEXT,
      icon_url TEXT,
      silent_install_args TEXT,
      silent_uninstall_args TEXT,
      detection_rule_json TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );

    CREATE TABLE IF NOT EXISTS policy_assignments (
      id TEXT PRIMARY KEY NOT NULL,
      group_id TEXT NOT NULL,
      software_id TEXT NOT NULL,
      assignment_type TEXT NOT NULL CHECK(assignment_type IN ('Required', 'Prohibited', 'Available')),
      auto_update INTEGER DEFAULT 1 CHECK(auto_update IN (0, 1)),
      enforcement_priority INTEGER DEFAULT 10,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(group_id) REFERENCES dynamic_groups(id) ON DELETE CASCADE,
      FOREIGN KEY(software_id) REFERENCES software_catalog(id) ON DELETE CASCADE,
      UNIQUE(group_id, software_id)
    );

    CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN (
        'USER_CREATED', 'USER_DELETED', 'ADMIN_ADDED', 'ADMIN_REMOVED',
        'APP_INSTALLED', 'APP_PROHIBITED_DETECTED', 'POLICY_DRIFT',
        'TPM_VIOLATION', 'SECUREBOOT_DISABLED', 'BITLOCKER_OFFLINE', 'WATCHDOG_HEARTBEAT'
      )),
      event_id INTEGER,
      event_source TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'WARNING')),
      summary TEXT NOT NULL,
      raw_payload_json TEXT NOT NULL,
      acknowledged INTEGER DEFAULT 0 CHECK(acknowledged IN (0, 1)),
      acknowledged_at TEXT,
      acknowledged_by TEXT,
      created_at TEXT NOT NULL DEFAULT (DATETIME('now')),
      FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS fleet_settings (
      key TEXT PRIMARY KEY NOT NULL,
      value TEXT NOT NULL,
      data_type TEXT DEFAULT 'string' CHECK(data_type IN ('string', 'number', 'boolean', 'json')),
      description TEXT,
      is_secret INTEGER DEFAULT 0 CHECK(is_secret IN (0, 1)),
      updated_at TEXT NOT NULL DEFAULT (DATETIME('now'))
    );
  `);

  // Insert seed data
  db.exec(`
    INSERT OR IGNORE INTO fleet_settings (key, value, data_type, description, is_secret) VALUES
    ('fleet_name', 'Daddy Command Fleet', 'string', 'Display title for dashboard header', 0),
    ('fleet_enrollment_key', '${DEFAULT_FLEET_KEY}', 'string', 'Pre-shared key required for new node enrollment', 1),
    ('server_port', '8443', 'number', 'Backend listening port', 0),
    ('heartbeat_interval_sec', '60', 'number', 'Frequency of lightweight node heartbeat', 0),
    ('telemetry_interval_min', '15', 'number', 'Frequency of deep hardware/software inventory harvest', 0),
    ('offline_threshold_sec', '180', 'number', 'Seconds without heartbeat before marking node offline', 0),
    ('discord_webhook_url', '', 'string', 'Discord Webhook URL for critical push notifications', 1),
    ('slack_webhook_url', '', 'string', 'Slack Incoming Webhook URL', 1),
    ('telegram_bot_token', '', 'string', 'Telegram Bot API Token', 1),
    ('telegram_chat_id', '', 'string', 'Telegram Chat ID for notifications', 0),
    ('toast_notifications_enabled', 'true', 'boolean', 'Show Windows native toast on Daddy PC', 0),
    ('cloudflare_tunnel_hostname', 'fleet.yourdomain.com', 'string', 'Public tunnel hostname', 0),
    ('cloudflare_tunnel_id', '98a72b14-41d3-469b-8411-9fa8e31201d4', 'string', 'Cloudflare Tunnel UUID', 0);

    INSERT OR IGNORE INTO dynamic_groups (id, name, description, rule_syntax, is_dynamic, color, icon, priority) VALUES
    ('grp-all', 'All Devices', 'Default catch-all group containing every enrolled node', 'Device.Hostname -like ''*''', 1, '#64748B', 'monitor', 10),
    ('grp-workstations', 'High-Performance Workstations', 'Powerful desktop rigs with >= 32GB RAM and dedicated NVIDIA GPU', 'Device.TotalRAM_GB -ge 32 and Device.GPU -like ''*NVIDIA*'' and Device.HasBattery -eq false', 1, '#10B981', 'cpu', 20),
    ('grp-family-laptops', 'Family Laptops', 'Portable battery-powered machines tagged for family members', 'Device.HasBattery -eq true and Device.Tags -contains ''family''', 1, '#3B82F6', 'laptop', 30),
    ('grp-win11-modern', 'Windows 11 Modern Core', 'Windows 11 builds with active TPM 2.0 and SecureBoot enabled', 'Device.OSVersion -like ''10.0.22*'' and Device.TPMEnabled -eq true and Device.SecureBoot -eq true', 1, '#8B5CF6', 'shield-check', 40),
    ('grp-low-storage', 'Storage Warning Watchlist', 'Nodes with less than 50GB free space on system drive', 'Device.StorageFree_GB -lt 50', 1, '#EF4444', 'hard-drive', 50);

    INSERT OR IGNORE INTO software_catalog (id, name, publisher, winget_id, version, category, description, silent_install_args) VALUES
    ('pkg-chrome', 'Google Chrome', 'Google LLC', 'Google.Chrome', 'latest', 'Browsers', 'Standard secure web browser', '--silent --accept-package-agreements --accept-source-agreements'),
    ('pkg-bitwarden', 'Bitwarden', 'Bitwarden Inc.', 'Bitwarden.Bitwarden', 'latest', 'Security', 'Password manager for family security', '--silent --accept-package-agreements --accept-source-agreements'),
    ('pkg-7zip', '7-Zip', 'Igor Pavlov', '7zip.7zip', 'latest', 'Utilities', 'Open source file archiver', '--silent --accept-package-agreements --accept-source-agreements'),
    ('pkg-vscode', 'Visual Studio Code', 'Microsoft Corporation', 'Microsoft.VisualStudioCode', 'latest', 'Development', 'Code editor for development workstations', '--silent --accept-package-agreements --accept-source-agreements'),
    ('pkg-steam', 'Steam', 'Valve Corporation', 'Valve.Steam', 'latest', 'Gaming', 'Gaming digital distribution platform', '--silent --accept-package-agreements --accept-source-agreements'),
    ('pkg-utorrent', 'uTorrent', 'BitTorrent Inc.', 'BitTorrent.uTorrent', '', 'Prohibited', 'Unapproved P2P torrent client', '--silent');

    INSERT OR IGNORE INTO policy_assignments (id, group_id, software_id, assignment_type, auto_update) VALUES
    ('pol-chrome-all', 'grp-all', 'pkg-chrome', 'Required', 1),
    ('pol-bitwarden-family', 'grp-family-laptops', 'pkg-bitwarden', 'Required', 1),
    ('pol-7zip-all', 'grp-all', 'pkg-7zip', 'Required', 1),
    ('pol-vscode-workstations', 'grp-workstations', 'pkg-vscode', 'Available', 1),
    ('pol-steam-workstations', 'grp-workstations', 'pkg-steam', 'Available', 1),
    ('pol-utorrent-prohibited-all', 'grp-all', 'pkg-utorrent', 'Prohibited', 0);
  `);

  return db;
}

/**
 * Entra ID-style Dynamic Group Expression Evaluator
 */
export function evaluateRule(ruleSyntax, deviceContext) {
  if (!ruleSyntax || typeof ruleSyntax !== 'string' || !ruleSyntax.trim()) {
    throw new Error('Empty rule syntax');
  }

  // Tokenize the expression
  const cleanRule = ruleSyntax.trim();

  // Basic validation for syntax structure
  // Evaluate AST / tokens
  function evalClause(propName, op, valStr) {
    const rawVal = resolveProperty(deviceContext, propName);
    const opLower = op.toLowerCase();

    // Parse target value
    let targetVal = parseValue(valStr);

    switch (opLower) {
      case '-eq':
      case 'eq':
        if (typeof rawVal === 'boolean' || typeof targetVal === 'boolean') {
          return Boolean(rawVal) === Boolean(targetVal);
        }
        if (typeof rawVal === 'number' || typeof targetVal === 'number') {
          return Number(rawVal) === Number(targetVal);
        }
        return String(rawVal ?? '').toLowerCase() === String(targetVal ?? '').toLowerCase();

      case '-ne':
      case 'ne':
        return !evalClause(propName, '-eq', valStr);

      case '-gt':
      case 'gt':
        return Number(rawVal) > Number(targetVal);

      case '-ge':
      case 'ge':
        return Number(rawVal) >= Number(targetVal);

      case '-lt':
      case 'lt':
        return Number(rawVal) < Number(targetVal);

      case '-le':
      case 'le':
        return Number(rawVal) <= Number(targetVal);

      case '-like':
      case 'like': {
        const pattern = String(targetVal ?? '').replace(/\*/g, '.*').replace(/\?/g, '.');
        const re = new RegExp(`^${pattern}$`, 'i');
        return re.test(String(rawVal ?? ''));
      }

      case '-notlike':
      case 'notlike': {
        const pattern = String(targetVal ?? '').replace(/\*/g, '.*').replace(/\?/g, '.');
        const re = new RegExp(`^${pattern}$`, 'i');
        return !re.test(String(rawVal ?? ''));
      }

      case '-contains':
      case 'contains': {
        if (Array.isArray(rawVal)) {
          return rawVal.some(item => String(item).toLowerCase() === String(targetVal).toLowerCase());
        }
        return String(rawVal ?? '').toLowerCase().includes(String(targetVal ?? '').toLowerCase());
      }

      case '-notcontains':
      case 'notcontains':
        return !evalClause(propName, '-contains', valStr);

      case '-in':
      case 'in': {
        if (Array.isArray(targetVal)) {
          return targetVal.some(item => String(item).toLowerCase() === String(rawVal).toLowerCase());
        }
        return false;
      }

      case '-notin':
      case 'notin':
        return !evalClause(propName, '-in', valStr);

      default:
        throw new Error(`Unsupported operator: ${op}`);
    }
  }

  function resolveProperty(ctx, path) {
    const key = path.replace(/^Device\./i, '');
    const map = {
      Hostname: ctx.hostname,
      FriendlyName: ctx.friendly_name,
      TotalRAM_GB: ctx.total_ram_gb !== undefined ? Number(ctx.total_ram_gb) : (ctx.total_ram_bytes ? ctx.total_ram_bytes / 1073741824 : 0),
      OSVersion: ctx.os_version,
      OSName: ctx.os_name,
      GPU: ctx.gpu_name,
      HasBattery: Boolean(ctx.has_battery),
      BatteryPercent: ctx.battery_percent !== undefined ? Number(ctx.battery_percent) : null,
      StorageFree_GB: ctx.storage_free_gb !== undefined ? Number(ctx.storage_free_gb) : (ctx.disk_free_gb ? Number(ctx.disk_free_gb) : 100),
      TPMEnabled: Boolean(ctx.tpm_enabled),
      TPMVersion: ctx.tpm_version,
      SecureBoot: Boolean(ctx.secure_boot_enabled),
      BitLocker: ctx.bitlocker_status,
      Group: ctx.assigned_group,
      Tags: Array.isArray(ctx.tags) ? ctx.tags : (typeof ctx.tags_json === 'string' ? JSON.parse(ctx.tags_json || '[]') : []),
      Route: ctx.connection_route,
      Status: ctx.status
    };
    return map[key] !== undefined ? map[key] : null;
  }

  function parseValue(valStr) {
    const trimmed = valStr.trim();
    if (/^true$/i.test(trimmed) || /^\$true$/i.test(trimmed)) return true;
    if (/^false$/i.test(trimmed) || /^\$false$/i.test(trimmed)) return false;
    if (/^-?\d+(\.\d+)?$/.test(trimmed)) return parseFloat(trimmed);
    if (/^['"].*['"]$/.test(trimmed)) return trimmed.slice(1, -1);
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const inside = trimmed.slice(1, -1).trim();
      if (!inside) return [];
      return inside.split(',').map(s => parseValue(s.trim()));
    }
    return trimmed;
  }

  // Split by OR groups
  const orParts = cleanRule.split(/\s+(?:-or|or)\s+/i);
  for (const orPart of orParts) {
    // Split by AND groups
    const andParts = orPart.split(/\s+(?:-and|and)\s+/i);
    let andMatch = true;

    for (const andPart of andParts) {
      const match = andPart.trim().match(/^(?:(-not|not)\s+)?(Device\.[a-zA-Z0-9_]+)\s+(-[a-zA-Z]+|[a-zA-Z]+)\s+('.*?'|".*?"|\[.*?\]|[^ ]+)$/i);
      if (!match) {
        throw new Error(`Malformed rule expression segment: "${andPart}"`);
      }
      const [, isNot, prop, op, val] = match;
      let res = evalClause(prop, op, val);
      if (isNot) res = !res;
      if (!res) {
        andMatch = false;
        break;
      }
    }

    if (andMatch) return true;
  }

  return false;
}

/**
 * Creates the Spec-Compliant Reference HTTP & SSE Server
 */
export function createContractServer(options = {}) {
  const db = options.db || initDatabase();
  const dispatchedAlerts = {
    toasts: [],
    discord: [],
    slack: [],
    telegram: [],
    events: []
  };

  const sseClients = new Set();

  function broadcastSSE(eventType, data) {
    const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of sseClients) {
      try {
        res.write(payload);
      } catch {
        sseClients.delete(res);
      }
    }
  }

  function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  function getSetting(key) {
    const row = db.prepare('SELECT value FROM fleet_settings WHERE key = ?').get(key);
    return row ? row.value : null;
  }

  function verifyFleetKey(req) {
    const key = req.headers['x-fleet-key'];
    const expected = getSetting('fleet_enrollment_key') || DEFAULT_FLEET_KEY;
    return key && key === expected;
  }

  function verifyNodeToken(req) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.slice(7).trim();
    const tokenHash = hashToken(token);
    const device = db.prepare('SELECT * FROM devices WHERE node_token_hash = ?').get(tokenHash);
    return device || null;
  }

  function recalculateDeviceMemberships(deviceId) {
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
    if (!device) return [];

    // Latest snapshot for storage free
    const latestSnap = db.prepare('SELECT disk_free_gb FROM telemetry_snapshots WHERE device_id = ? ORDER BY id DESC LIMIT 1').get(deviceId);
    const devContext = { ...device, disk_free_gb: latestSnap ? latestSnap.disk_free_gb : 100 };

    const groups = db.prepare('SELECT * FROM dynamic_groups WHERE is_dynamic = 1').all();
    const matchedGroupIds = [];

    for (const grp of groups) {
      try {
        if (evaluateRule(grp.rule_syntax, devContext)) {
          matchedGroupIds.push(grp.id);
          db.prepare(`
            INSERT INTO group_memberships (group_id, device_id, is_dynamic_match, evaluated_at)
            VALUES (?, ?, 1, DATETIME('now'))
            ON CONFLICT(group_id, device_id) DO UPDATE SET evaluated_at = DATETIME('now')
          `).run(grp.id, deviceId);
        } else {
          db.prepare('DELETE FROM group_memberships WHERE group_id = ? AND device_id = ? AND is_dynamic_match = 1').run(grp.id, deviceId);
        }
      } catch {
        // Fail-safe on malformed rule
      }
    }

    return matchedGroupIds;
  }

  const server = http.createServer(async (req, res) => {
    // Detect connection route from Cloudflare headers
    const isCloudflare = Boolean(req.headers['cf-connecting-ip'] || req.headers['cf-ray']);
    const detectedRoute = isCloudflare ? 'Cloudflare' : 'LAN';

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // Helper to read JSON body
    async function readJson() {
      return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
          body += chunk;
          if (body.length > 5 * 1024 * 1024) {
            reject(new Error('Payload too large'));
          }
        });
        req.on('end', () => {
          if (!body.trim()) {
            resolve({});
            return;
          }
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(e);
          }
        });
      });
    }

    function sendJson(status, obj) {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(obj));
    }

    // CORS & Common headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Fleet-Key');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      // -------------------------------------------------------------
      // Health check
      // -------------------------------------------------------------
      if (pathname === '/api/v1/health' && req.method === 'GET') {
        return sendJson(200, { status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0' });
      }

      // -------------------------------------------------------------
      // Static Dashboard Route
      // -------------------------------------------------------------
      if ((pathname === '/' || pathname === '/index.html') && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><head><title>LocalPilot Fleet Command Center</title></head><body style="background:#080c14;color:#fff;"><h1>LocalPilot Fleet Command Center</h1></body></html>`);
        return;
      }

      // -------------------------------------------------------------
      // Node Enrollment: POST /api/v1/nodes/enroll
      // -------------------------------------------------------------
      if (pathname === '/api/v1/nodes/enroll' && req.method === 'POST') {
        if (!verifyFleetKey(req)) {
          return sendJson(401, { error: 'INVALID_FLEET_KEY', message: 'Invalid or missing X-Fleet-Key' });
        }

        let body;
        try {
          body = await readJson();
        } catch {
          return sendJson(400, { error: 'BAD_REQUEST', message: 'Malformed JSON payload' });
        }

        if (!body.hostname) {
          return sendJson(400, { error: 'BAD_REQUEST', message: 'Missing required field: hostname' });
        }

        const deviceId = body.uuid || crypto.randomUUID();
        const rawToken = `lp_node_${crypto.randomBytes(18).toString('hex')}`;
        const tokenHash = hashToken(rawToken);

        const serialNumber = body.serial_number || `SN-${crypto.randomBytes(6).toString('hex')}`;
        const ramBytes = body.total_ram_bytes !== undefined ? Number(body.total_ram_bytes) : 17179869184;
        const friendlyName = body.friendly_name !== undefined ? body.friendly_name : body.hostname;
        const tagsJson = JSON.stringify(Array.isArray(body.tags) ? body.tags : []);

        // Check if device with same serial exists
        const existing = db.prepare('SELECT id FROM devices WHERE serial_number = ? OR uuid = ?').get(serialNumber, body.uuid || '');

        let assignedId = deviceId;
        if (existing) {
          assignedId = existing.id;
          db.prepare(`
            UPDATE devices SET
              hostname = ?, friendly_name = ?, ip_address = ?, connection_route = ?,
              os_name = ?, os_version = ?, os_build = ?, cpu_model = ?, cpu_cores = ?,
              total_ram_bytes = ?, gpu_name = ?, has_battery = ?, tpm_present = ?,
              tpm_version = ?, tpm_enabled = ?, secure_boot_enabled = ?, bitlocker_status = ?,
              primary_user = ?, tags_json = ?, node_token_hash = ?, agent_version = ?,
              status = 'online', last_seen_at = DATETIME('now'), updated_at = DATETIME('now')
            WHERE id = ?
          `).run(
            body.hostname, friendlyName, body.ip_address || '127.0.0.1', detectedRoute,
            body.os_name || 'Windows 11', body.os_version || '10.0.22631', body.os_build || '22631',
            body.cpu_model || 'Generic CPU', Number(body.cpu_cores) || 4, ramBytes,
            body.gpu_name || 'Generic GPU', body.has_battery ? 1 : 0, body.tpm_present ? 1 : 0,
            body.tpm_version || '2.0', body.tpm_enabled ? 1 : 0, body.secure_boot_enabled ? 1 : 0,
            body.bitlocker_status || 'Disabled', body.primary_user || 'User', tagsJson, tokenHash,
            body.agent_version || '1.0.0', assignedId
          );
        } else {
          db.prepare(`
            INSERT INTO devices (
              id, hostname, friendly_name, serial_number, uuid, mac_address, ip_address,
              connection_route, status, os_name, os_version, os_build, os_architecture,
              cpu_model, cpu_cores, cpu_logical, total_ram_bytes, gpu_name, has_battery,
              battery_percent, tpm_present, tpm_version, tpm_enabled, secure_boot_enabled,
              bitlocker_status, primary_user, tags_json, assigned_group, node_token_hash,
              agent_version
            ) VALUES (
              ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
          `).run(
            assignedId, body.hostname, friendlyName, serialNumber,
            body.uuid || assignedId, body.mac_address || '00:00:00:00:00:00', body.ip_address || '127.0.0.1',
            detectedRoute, body.os_name || 'Windows 11', body.os_version || '10.0.22631',
            body.os_build || '22631', body.os_architecture || '64-bit', body.cpu_model || 'Generic CPU',
            Number(body.cpu_cores) || 4, Number(body.cpu_logical) || 8, ramBytes,
            body.gpu_name || 'Generic GPU', body.has_battery ? 1 : 0, body.battery_percent || null,
            body.tpm_present ? 1 : 0, body.tpm_version || '2.0', body.tpm_enabled ? 1 : 0,
            body.secure_boot_enabled ? 1 : 0, body.bitlocker_status || 'Disabled',
            body.primary_user || 'User', tagsJson, body.assigned_group || 'Family', tokenHash,
            body.agent_version || '1.0.0'
          );
        }

        const activeGroups = recalculateDeviceMemberships(assignedId);

        return sendJson(201, {
          status: 'enrolled',
          device_id: assignedId,
          node_token: rawToken,
          heartbeat_interval_sec: 60,
          telemetry_interval_min: 15,
          assigned_groups: activeGroups
        });
      }

      // -------------------------------------------------------------
      // Node Heartbeat: POST /api/v1/nodes/heartbeat
      // -------------------------------------------------------------
      if (pathname === '/api/v1/nodes/heartbeat' && req.method === 'POST') {
        const device = verifyNodeToken(req);
        if (!device) {
          return sendJson(401, { error: 'INVALID_NODE_TOKEN', message: 'Unauthorized node token' });
        }

        const body = await readJson();
        const route = isCloudflare ? 'Cloudflare' : (body.connection_route || detectedRoute);

        db.prepare(`
          UPDATE devices SET
            status = 'online',
            connection_route = ?,
            ip_address = COALESCE(?, ip_address),
            battery_percent = COALESCE(?, battery_percent),
            battery_charging = COALESCE(?, battery_charging),
            last_seen_at = DATETIME('now'),
            updated_at = DATETIME('now')
          WHERE id = ?
        `).run(route, body.ip_address || null, body.battery_percent || null, body.battery_charging ? 1 : 0, device.id);

        broadcastSSE('heartbeat', {
          device_id: device.id,
          hostname: device.hostname,
          status: 'online',
          cpu: body.cpu_usage_percent || 0,
          ram_pct: body.ram_usage_percent || 0,
          route,
          timestamp: new Date().toISOString()
        });

        return sendJson(200, {
          acknowledged: true,
          server_time: new Date().toISOString(),
          commands_pending: false
        });
      }

      // -------------------------------------------------------------
      // Node Telemetry Ingestion: POST /api/v1/nodes/telemetry
      // -------------------------------------------------------------
      if (pathname === '/api/v1/nodes/telemetry' && req.method === 'POST') {
        const device = verifyNodeToken(req);
        if (!device) {
          return sendJson(401, { error: 'INVALID_NODE_TOKEN', message: 'Unauthorized node token' });
        }

        const body = await readJson();
        const hw = body.hardware || {};
        const disks = hw.disks || [];
        const systemDisk = disks.find(d => d.drive_letter === 'C:' || d.drive === 'C:') || disks[0] || {};
        const freeGb = systemDisk.free_gb || 100;

        // Insert telemetry snapshot
        db.prepare(`
          INSERT INTO telemetry_snapshots (
            device_id, cpu_usage_percent, ram_used_bytes, ram_free_bytes,
            ram_usage_percent, disk_free_gb, disks_json, network_json,
            battery_percent, battery_charging, uptime_seconds
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          device.id,
          hw.cpu_usage_percent || 0,
          hw.ram_used_bytes || 0,
          hw.ram_free_bytes || 0,
          hw.ram_usage_percent || 0,
          freeGb,
          JSON.stringify(disks),
          JSON.stringify(hw.network_adapters || []),
          body.battery_percent || null,
          body.battery_charging ? 1 : 0,
          body.uptime_seconds || 0
        );

        // Update device columns
        db.prepare(`
          UPDATE devices SET
            last_seen_at = DATETIME('now'),
            connection_route = ?,
            status = 'online',
            updated_at = DATETIME('now')
          WHERE id = ?
        `).run(detectedRoute, device.id);

        const activeGroups = recalculateDeviceMemberships(device.id);

        // Check for prohibited software
        const installedSoftware = body.installed_software || [];
        const prohibitedList = db.prepare(`
          SELECT sc.winget_id, sc.name
          FROM policy_assignments pa
          JOIN software_catalog sc ON pa.software_id = sc.id
          WHERE pa.assignment_type = 'Prohibited'
        `).all();

        const driftReasons = [];
        for (const proh of prohibitedList) {
          const match = installedSoftware.find(app =>
            (app.winget_id && app.winget_id.toLowerCase() === proh.winget_id.toLowerCase()) ||
            (app.name && app.name.toLowerCase().includes(proh.name.toLowerCase()))
          );
          if (match) {
            driftReasons.push(`Prohibited package '${proh.name}' detected on node`);
          }
        }

        let driftDetected = driftReasons.length > 0;
        if (driftDetected) {
          db.prepare("UPDATE devices SET status = 'drifted' WHERE id = ?").run(device.id);
          db.prepare(`
            INSERT INTO security_events (device_id, event_type, event_id, event_source, severity, summary, raw_payload_json)
            VALUES (?, 'APP_PROHIBITED_DETECTED', 1033, 'LocalPilotWatchdog', 'CRITICAL', ?, ?)
          `).run(
            device.id,
            `Prohibited application detected: ${driftReasons.join(', ')}`,
            JSON.stringify({ drift_reasons: driftReasons, installed: installedSoftware })
          );
        }

        const policyCount = db.prepare(`
          SELECT COUNT(*) as count FROM policy_assignments pa
          JOIN group_memberships gm ON pa.group_id = gm.group_id
          WHERE gm.device_id = ?
        `).get(device.id).count;

        return sendJson(200, {
          status: 'processed',
          group_reevaluated: true,
          active_groups: activeGroups,
          policies_count: policyCount,
          drift_detected: driftDetected,
          drift_reasons: driftReasons
        });
      }

      // -------------------------------------------------------------
      // Security Event Ingest: POST /api/v1/nodes/events
      // -------------------------------------------------------------
      if (pathname === '/api/v1/nodes/events' && req.method === 'POST') {
        const device = verifyNodeToken(req);
        if (!device) {
          return sendJson(401, { error: 'INVALID_NODE_TOKEN', message: 'Unauthorized node token' });
        }

        let body;
        try {
          body = await readJson();
        } catch {
          return sendJson(400, { error: 'BAD_REQUEST', message: 'Malformed JSON' });
        }

        if (!body.event_type || !body.severity) {
          return sendJson(400, { error: 'BAD_REQUEST', message: 'Missing required event fields' });
        }

        const resDb = db.prepare(`
          INSERT INTO security_events (
            device_id, event_type, event_id, event_source, severity, summary, raw_payload_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          device.id,
          body.event_type,
          body.event_id || 0,
          body.event_source || 'Security',
          body.severity,
          body.summary || `Event ${body.event_type} on ${device.hostname}`,
          JSON.stringify(body.details || {})
        );

        const eventId = Number(resDb.lastInsertRowid);

        // Record dispatch for testing verification
        dispatchedAlerts.events.push({ id: eventId, deviceId: device.id, ...body });
        if (body.severity === 'CRITICAL' || body.severity === 'HIGH') {
          dispatchedAlerts.toasts.push({ title: 'LocalPilot Security Alert', body: body.summary });
          dispatchedAlerts.discord.push({ eventId, summary: body.summary });
          dispatchedAlerts.slack.push({ eventId, summary: body.summary });
          dispatchedAlerts.telegram.push({ eventId, summary: body.summary });
        }

        broadcastSSE('security_alert', {
          id: eventId,
          device_id: device.id,
          hostname: device.hostname,
          severity: body.severity,
          event_type: body.event_type,
          summary: body.summary,
          timestamp: new Date().toISOString()
        });

        return sendJson(202, {
          status: 'dispatched',
          event_record_id: eventId,
          toast_fired: true,
          webhooks_dispatched: ['discord', 'slack', 'telegram']
        });
      }

      // -------------------------------------------------------------
      // Node Policy Query: GET /api/v1/nodes/:id/policy
      // -------------------------------------------------------------
      const nodePolicyMatch = pathname.match(/^\/api\/v1\/nodes\/([^/]+)\/policy$/);
      if (nodePolicyMatch && req.method === 'GET') {
        const targetDeviceId = nodePolicyMatch[1];
        const device = verifyNodeToken(req);
        const isAdmin = verifyFleetKey(req);

        if (!isAdmin && (!device || device.id !== targetDeviceId)) {
          return sendJson(401, { error: 'UNAUTHORIZED', message: 'Access denied' });
        }

        const devRecord = db.prepare('SELECT * FROM devices WHERE id = ?').get(targetDeviceId);
        if (!devRecord) {
          return sendJson(404, { error: 'NOT_FOUND', message: 'Device not found' });
        }

        const assignedGroups = db.prepare(`
          SELECT dg.id, dg.name
          FROM group_memberships gm
          JOIN dynamic_groups dg ON gm.group_id = dg.id
          WHERE gm.device_id = ?
        `).all(targetDeviceId);

        const groupIds = assignedGroups.map(g => g.id);
        const policies = { required: [], prohibited: [], available: [] };

        if (groupIds.length > 0) {
          const placeholders = groupIds.map(() => '?').join(',');
          const rows = db.prepare(`
            SELECT pa.assignment_type, sc.id as software_id, sc.name, sc.winget_id, sc.silent_install_args, sc.silent_uninstall_args
            FROM policy_assignments pa
            JOIN software_catalog sc ON pa.software_id = sc.id
            WHERE pa.group_id IN (${placeholders})
          `).all(...groupIds);

          for (const row of rows) {
            if (row.assignment_type === 'Required') {
              policies.required.push({
                software_id: row.software_id,
                name: row.name,
                winget_id: row.winget_id,
                silent_install_args: row.silent_install_args,
                auto_update: true
              });
            } else if (row.assignment_type === 'Prohibited') {
              policies.prohibited.push({
                software_id: row.software_id,
                name: row.name,
                winget_id: row.winget_id,
                silent_uninstall_args: row.silent_uninstall_args,
                action: 'uninstall_and_alert'
              });
            } else if (row.assignment_type === 'Available') {
              policies.available.push({
                software_id: row.software_id,
                name: row.name,
                winget_id: row.winget_id
              });
            }
          }
        }

        return sendJson(200, {
          device_id: targetDeviceId,
          generated_at: new Date().toISOString(),
          assigned_groups: assignedGroups,
          policies
        });
      }

      // -------------------------------------------------------------
      // Dashboard Endpoints: /api/v1/fleet/*
      // -------------------------------------------------------------
      if (pathname.startsWith('/api/v1/fleet/')) {
        // SSE stream handles auth or connects
        if (pathname === '/api/v1/fleet/events/stream' && req.method === 'GET') {
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
          });
          res.write(`event: connected\ndata: {"status":"connected","time":"${new Date().toISOString()}"}\n\n`);
          sseClients.add(res);
          req.on('close', () => {
            sseClients.delete(res);
          });
          return;
        }

        // Fleet key required for administrative endpoints
        if (!verifyFleetKey(req)) {
          return sendJson(401, { error: 'INVALID_FLEET_KEY', message: 'FleetKey required for admin operations' });
        }

        // Executive KPI Overview: GET /api/v1/fleet/stats
        if (pathname === '/api/v1/fleet/stats' && req.method === 'GET') {
          const totalDevices = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
          const onlineCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'online'").get().count;
          const offlineCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'offline'").get().count;
          const driftedCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'drifted'").get().count;
          const critAlerts = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE severity = 'CRITICAL' AND acknowledged = 0").get().count;
          const totalRam = db.prepare('SELECT SUM(total_ram_gb) as sum FROM devices').get().sum || 0;

          return sendJson(200, {
            total_devices: totalDevices,
            online: onlineCount,
            offline: offlineCount,
            drifted: driftedCount,
            critical_alerts: critAlerts,
            total_fleet_ram_gb: Math.round(totalRam),
            total_fleet_storage_tb: 2.4
          });
        }

        // Device Inventory: GET /api/v1/fleet/devices
        if (pathname === '/api/v1/fleet/devices' && req.method === 'GET') {
          const search = url.searchParams.get('search') || '';
          const status = url.searchParams.get('status');
          const route = url.searchParams.get('route');

          let query = 'SELECT * FROM devices WHERE 1=1';
          const params = [];

          if (search) {
            query += ' AND (hostname LIKE ? OR ip_address LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
          }
          if (status) {
            query += ' AND status = ?';
            params.push(status);
          }
          if (route) {
            query += ' AND connection_route = ?';
            params.push(route);
          }

          const devices = db.prepare(query).all(...params);
          return sendJson(200, { devices, total_count: devices.length });
        }

        // Deep Inspection: GET /api/v1/fleet/devices/:id
        const devIdMatch = pathname.match(/^\/api\/v1\/fleet\/devices\/([^/]+)$/);
        if (devIdMatch && req.method === 'GET') {
          const id = devIdMatch[1];
          const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
          if (!dev) return sendJson(404, { error: 'NOT_FOUND', message: 'Device not found' });

          const latestSnap = db.prepare('SELECT * FROM telemetry_snapshots WHERE device_id = ? ORDER BY id DESC LIMIT 1').get(id);
          const groups = db.prepare(`
            SELECT dg.* FROM dynamic_groups dg
            JOIN group_memberships gm ON dg.id = gm.group_id
            WHERE gm.device_id = ?
          `).all(id);

          return sendJson(200, {
            device: dev,
            latest_telemetry: latestSnap || null,
            groups
          });
        }

        // Update Device: PATCH /api/v1/fleet/devices/:id
        if (devIdMatch && req.method === 'PATCH') {
          const id = devIdMatch[1];
          const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
          if (!dev) return sendJson(404, { error: 'NOT_FOUND', message: 'Device not found' });

          const body = await readJson();
          if (body.friendly_name !== undefined) {
            db.prepare('UPDATE devices SET friendly_name = ? WHERE id = ?').run(body.friendly_name, id);
          }
          if (body.tags !== undefined) {
            db.prepare('UPDATE devices SET tags_json = ? WHERE id = ?').run(JSON.stringify(body.tags), id);
          }
          if (body.assigned_group !== undefined) {
            db.prepare('UPDATE devices SET assigned_group = ? WHERE id = ?').run(body.assigned_group, id);
          }

          recalculateDeviceMemberships(id);
          return sendJson(200, { updated: true });
        }

        // Delete Device: DELETE /api/v1/fleet/devices/:id
        if (devIdMatch && req.method === 'DELETE') {
          const id = devIdMatch[1];
          const dev = db.prepare('SELECT * FROM devices WHERE id = ?').get(id);
          if (!dev) return sendJson(404, { error: 'NOT_FOUND', message: 'Device not found' });

          db.prepare('DELETE FROM devices WHERE id = ?').run(id);
          return sendJson(200, { deleted: true, message: 'Node removed' });
        }

        // Dynamic Groups: GET /api/v1/fleet/groups
        if (pathname === '/api/v1/fleet/groups' && req.method === 'GET') {
          const groups = db.prepare(`
            SELECT dg.*, COUNT(gm.device_id) as member_count
            FROM dynamic_groups dg
            LEFT JOIN group_memberships gm ON dg.id = gm.group_id
            GROUP BY dg.id
            ORDER BY dg.priority ASC
          `).all();
          return sendJson(200, groups);
        }

        // Create Dynamic Group: POST /api/v1/fleet/groups
        if (pathname === '/api/v1/fleet/groups' && req.method === 'POST') {
          const body = await readJson();
          if (!body.name || !body.rule_syntax) {
            return sendJson(400, { error: 'BAD_REQUEST', message: 'Missing name or rule_syntax' });
          }

          // Test syntax validation
          try {
            evaluateRule(body.rule_syntax, { hostname: 'TEST', total_ram_bytes: 1073741824 });
          } catch (e) {
            return sendJson(400, { error: 'INVALID_SYNTAX', message: e.message });
          }

          const groupId = body.id || `grp-${crypto.randomBytes(4).toString('hex')}`;
          try {
            db.prepare(`
              INSERT INTO dynamic_groups (id, name, description, rule_syntax, color, icon, priority)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(
              groupId, body.name, body.description || '', body.rule_syntax,
              body.color || '#3B82F6', body.icon || 'laptop', body.priority || 100
            );
          } catch (e) {
            return sendJson(400, { error: 'DUPLICATE_GROUP', message: e.message });
          }

          // Evaluate for all devices
          const allDevs = db.prepare('SELECT id FROM devices').all();
          for (const d of allDevs) recalculateDeviceMemberships(d.id);

          return sendJson(201, { group_id: groupId, status: 'created' });
        }

        // Dry-run Evaluate Group Rule: POST /api/v1/fleet/groups/evaluate
        if (pathname === '/api/v1/fleet/groups/evaluate' && req.method === 'POST') {
          const body = await readJson();
          if (!body.rule_syntax) {
            return sendJson(400, { error: 'BAD_REQUEST', message: 'Missing rule_syntax' });
          }

          const matchedDevices = [];
          const devices = db.prepare('SELECT * FROM devices').all();

          try {
            for (const d of devices) {
              if (evaluateRule(body.rule_syntax, d)) {
                matchedDevices.push(d.id);
              }
            }
          } catch (e) {
            return sendJson(400, { valid: false, error: e.message });
          }

          return sendJson(200, { valid: true, matched_devices: matchedDevices, total_matches: matchedDevices.length });
        }

        // Software Catalog: GET /api/v1/fleet/software
        if (pathname === '/api/v1/fleet/software' && req.method === 'GET') {
          const software = db.prepare('SELECT * FROM software_catalog').all();
          return sendJson(200, software);
        }

        // Add Software Catalog: POST /api/v1/fleet/software
        if (pathname === '/api/v1/fleet/software' && req.method === 'POST') {
          const body = await readJson();
          if (!body.name || !body.winget_id) {
            return sendJson(400, { error: 'BAD_REQUEST', message: 'Missing name or winget_id' });
          }
          const pkgId = body.id || `pkg-${crypto.randomBytes(4).toString('hex')}`;
          try {
            db.prepare(`
              INSERT INTO software_catalog (id, name, publisher, winget_id, version, category, description, silent_install_args)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
              pkgId, body.name, body.publisher || '', body.winget_id, body.version || 'latest',
              body.category || 'Utilities', body.description || '', body.silent_install_args || '--silent'
            );
          } catch (e) {
            return sendJson(400, { error: 'CATALOG_ERROR', message: e.message });
          }
          return sendJson(201, { id: pkgId, status: 'created' });
        }

        // Policy Assignments: GET /api/v1/fleet/policies
        if (pathname === '/api/v1/fleet/policies' && req.method === 'GET') {
          const catalog = db.prepare('SELECT * FROM software_catalog').all();
          const assignments = db.prepare(`
            SELECT pa.*, sc.name as software_name, sc.winget_id, dg.name as group_name
            FROM policy_assignments pa
            JOIN software_catalog sc ON pa.software_id = sc.id
            JOIN dynamic_groups dg ON pa.group_id = dg.id
          `).all();
          return sendJson(200, { catalog, assignments });
        }

        // Set Policy Assignment: PUT /api/v1/fleet/policies
        if (pathname === '/api/v1/fleet/policies' && req.method === 'PUT') {
          const body = await readJson();
          if (!body.group_id || !body.software_id || !body.assignment_type) {
            return sendJson(400, { error: 'BAD_REQUEST', message: 'Missing assignment parameters' });
          }
          const polId = `pol-${crypto.randomBytes(4).toString('hex')}`;
          db.prepare(`
            INSERT INTO policy_assignments (id, group_id, software_id, assignment_type)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(group_id, software_id) DO UPDATE SET
              assignment_type = excluded.assignment_type,
              updated_at = DATETIME('now')
          `).run(polId, body.group_id, body.software_id, body.assignment_type);

          return sendJson(200, { assigned: true });
        }

        // Audit Events: GET /api/v1/fleet/events
        if (pathname === '/api/v1/fleet/events' && req.method === 'GET') {
          const sev = url.searchParams.get('severity');
          let query = 'SELECT se.*, d.hostname FROM security_events se JOIN devices d ON se.device_id = d.id WHERE 1=1';
          const params = [];
          if (sev) {
            query += ' AND se.severity = ?';
            params.push(sev);
          }
          query += ' ORDER BY se.id DESC LIMIT 100';
          const events = db.prepare(query).all(...params);
          return sendJson(200, events);
        }

        // Acknowledge Alert: POST /api/v1/fleet/events/:id/ack
        const ackMatch = pathname.match(/^\/api\/v1\/fleet\/events\/([^/]+)\/ack$/);
        if (ackMatch && req.method === 'POST') {
          const eventId = ackMatch[1];
          const evt = db.prepare('SELECT id FROM security_events WHERE id = ?').get(eventId);
          if (!evt) {
            return sendJson(404, { error: 'NOT_FOUND', message: 'Event not found' });
          }
          db.prepare(`
            UPDATE security_events SET
              acknowledged = 1,
              acknowledged_at = DATETIME('now'),
              acknowledged_by = 'Dad'
            WHERE id = ?
          `).run(eventId);

          return sendJson(200, { acknowledged: true, event_id: eventId });
        }

        // Settings: GET /api/v1/fleet/settings
        if (pathname === '/api/v1/fleet/settings' && req.method === 'GET') {
          const rows = db.prepare('SELECT key, value, data_type, description, is_secret FROM fleet_settings').all();
          const masked = rows.map(r => ({
            ...r,
            value: r.is_secret && r.value ? '••••••••' : r.value
          }));
          return sendJson(200, masked);
        }

        // Update Settings: PUT /api/v1/fleet/settings
        if (pathname === '/api/v1/fleet/settings' && req.method === 'PUT') {
          const body = await readJson();
          for (const [k, v] of Object.entries(body)) {
            db.prepare('UPDATE fleet_settings SET value = ?, updated_at = DATETIME(\'now\') WHERE key = ?').run(String(v), k);
          }
          return sendJson(200, { success: true });
        }

        // Cloudflare Tunnel Generator: POST /api/v1/fleet/tunnel/generate
        if (pathname === '/api/v1/fleet/tunnel/generate' && req.method === 'POST') {
          const body = await readJson();
          const host = body.hostname || 'fleet.yourdomain.com';
          const port = getSetting('server_port') || '8443';
          const tunnelId = getSetting('cloudflare_tunnel_id') || '98a72b14-41d3-469b-8411-9fa8e31201d4';

          const configYaml = `tunnel: ${tunnelId}
credentials-file: C:\\ProgramData\\cloudflared\\${tunnelId}.json

ingress:
  - hostname: ${host}
    service: http://localhost:${port}
    originRequest:
      noTLSVerify: true
  - hostname: ${host}
    path: /api/v1/fleet/events/stream
    service: http://localhost:${port}
    originRequest:
      noTLSVerify: true
      tcpKeepAlive: 30s
  - service: http_status:404
`;
          return sendJson(200, {
            config_yml: configYaml,
            hostname: host,
            powershell_setup: `cloudflared service install`
          });
        }

        // Cloudflare Tunnel Status: GET /api/v1/fleet/tunnel/status
        if (pathname === '/api/v1/fleet/tunnel/status' && req.method === 'GET') {
          return sendJson(200, {
            installed: true,
            running: true,
            active_connections: 2,
            hostname: getSetting('cloudflare_tunnel_hostname') || 'fleet.yourdomain.com'
          });
        }
      }

      // Not found
      return sendJson(404, { error: 'NOT_FOUND', message: `Route ${req.method} ${pathname} not found` });

    } catch (err) {
      return sendJson(500, { error: 'INTERNAL_ERROR', message: err.message });
    }
  });

  return {
    server,
    db,
    dispatchedAlerts,
    start: (port = 0) => new Promise((resolve) => {
      server.listen(port, () => {
        const address = server.address();
        resolve({
          port: address.port,
          url: `http://localhost:${address.port}`
        });
      });
    }),
    stop: () => new Promise((resolve) => {
      for (const res of sseClients) {
        try { res.end(); } catch {}
      }
      sseClients.clear();
      server.close(() => resolve());
    })
  };
}
