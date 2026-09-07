/**
 * LocalPilot Fleet — Dynamic Group Expression AST Engine
 * server/src/services/dynamicGroups.js
 *
 * Implements an Entra ID / PowerShell style dynamic rule parser and evaluator.
 * Operates without eval() or dangerous code execution.
 *
 * Operators supported:
 * - Equality: -eq, -ne
 * - Relational: -gt, -ge, -lt, -le
 * - Wildcards: -like, -notlike
 * - Collection: -contains, -notcontains
 * - Set inclusion: -in, -notin
 * - Logical: and, -and, or, -or, not, -not
 */

const astCache = new Map();
const regexCache = new Map();
const MAX_RULE_LENGTH = 4096;

export const PROPERTY_MAP = {
  'hostname': 'hostname',
  'friendlyname': 'friendly_name',
  'friendly_name': 'friendly_name',
  'totalram_gb': 'total_ram_gb',
  'totalram': 'total_ram_gb',
  'osversion': 'os_version',
  'os_version': 'os_version',
  'osname': 'os_name',
  'os_name': 'os_name',
  'osbuild': 'os_build',
  'os_build': 'os_build',
  'gpu': 'gpu_name',
  'gpuname': 'gpu_name',
  'gpu_name': 'gpu_name',
  'hasbattery': 'has_battery',
  'has_battery': 'has_battery',
  'batterypercent': 'battery_percent',
  'battery_percent': 'battery_percent',
  'storagefree_gb': 'storage_free_gb',
  'storage_free_gb': 'storage_free_gb',
  'diskfree_gb': 'storage_free_gb',
  'disk_free_gb': 'storage_free_gb',
  'tpmenabled': 'tpm_enabled',
  'tpm_enabled': 'tpm_enabled',
  'tpmversion': 'tpm_version',
  'tpm_version': 'tpm_version',
  'secureboot': 'secure_boot_enabled',
  'securebootenabled': 'secure_boot_enabled',
  'secure_boot_enabled': 'secure_boot_enabled',
  'bitlocker': 'bitlocker_status',
  'bitlockerstatus': 'bitlocker_status',
  'bitlocker_status': 'bitlocker_status',
  'group': 'assigned_group',
  'assignedgroup': 'assigned_group',
  'assigned_group': 'assigned_group',
  'tags': 'tags',
  'status': 'status',
  'route': 'connection_route',
  'connectionroute': 'connection_route',
  'connection_route': 'connection_route',
  'installedapps': 'installed_apps',
  'installed_apps': 'installed_apps'
};

export class Lexer {
  constructor(input) {
    if (typeof input !== 'string') {
      throw new TypeError('Rule input must be a string');
    }
    if (input.length > MAX_RULE_LENGTH) {
      throw new Error(`Rule exceeds maximum length of ${MAX_RULE_LENGTH} characters`);
    }
    this.input = input.trim();
    this.pos = 0;
    this.len = this.input.length;
  }

  skipWhitespace() {
    while (this.pos < this.len && /\s/.test(this.input[this.pos])) {
      this.pos++;
    }
  }

  tokenize() {
    const tokens = [];
    while (this.pos < this.len) {
      this.skipWhitespace();
      if (this.pos >= this.len) break;

      const ch = this.input[this.pos];

      if (ch === '(') {
        tokens.push({ type: 'LPAREN', value: '(' });
        this.pos++;
      } else if (ch === ')') {
        tokens.push({ type: 'RPAREN', value: ')' });
        this.pos++;
      } else if (ch === '[' || ch === '{') {
        tokens.push({ type: 'LBRACKET', value: '[' });
        this.pos++;
      } else if (ch === ']' || ch === '}') {
        tokens.push({ type: 'RBRACKET', value: ']' });
        this.pos++;
      } else if (ch === ',') {
        tokens.push({ type: 'COMMA', value: ',' });
        this.pos++;
      } else if (ch === "'" || ch === '"') {
        tokens.push(this.readString(ch));
      } else if (ch === '-' && this.pos + 1 < this.len && /[a-zA-Z]/.test(this.input[this.pos + 1])) {
        tokens.push(this.readOperatorOrWord());
      } else if (ch === '-' || ch === '+' || /[0-9]/.test(ch)) {
        tokens.push(this.readNumber());
      } else if (/[a-zA-Z_$]/.test(ch)) {
        tokens.push(this.readIdentifierOrKeyword());
      } else {
        throw new SyntaxError(`Unexpected character '${ch}' at index ${this.pos}`);
      }
    }

    tokens.push({ type: 'EOF', value: null });
    return tokens;
  }

  readString(quote) {
    this.pos++; // skip opening quote
    let result = '';
    while (this.pos < this.len) {
      const ch = this.input[this.pos];
      if (ch === quote) {
        // Check for double-quote escaping '' or ""
        if (this.pos + 1 < this.len && this.input[this.pos + 1] === quote) {
          result += quote;
          this.pos += 2;
          continue;
        }
        this.pos++; // skip closing quote
        return { type: 'STRING', value: result };
      } else if (ch === '\\' && this.pos + 1 < this.len) {
        const nextChar = this.input[this.pos + 1];
        if (nextChar === quote || nextChar === '\\') {
          result += nextChar;
          this.pos += 2;
        } else if (nextChar === 'n') {
          result += '\n';
          this.pos += 2;
        } else if (nextChar === 't') {
          result += '\t';
          this.pos += 2;
        } else {
          result += nextChar;
          this.pos += 2;
        }
      } else {
        result += ch;
        this.pos++;
      }
    }
    throw new SyntaxError('Unterminated string literal');
  }

  readNumber() {
    const start = this.pos;
    if (this.input[this.pos] === '-' || this.input[this.pos] === '+') {
      this.pos++;
    }
    let hasDot = false;
    while (this.pos < this.len) {
      const ch = this.input[this.pos];
      if (/[0-9]/.test(ch)) {
        this.pos++;
      } else if (ch === '.' && !hasDot && this.pos + 1 < this.len && /[0-9]/.test(this.input[this.pos + 1])) {
        hasDot = true;
        this.pos++;
      } else {
        break;
      }
    }
    const numStr = this.input.slice(start, this.pos);
    const num = Number(numStr);
    if (isNaN(num)) {
      throw new SyntaxError(`Invalid numeric literal: '${numStr}'`);
    }
    return { type: 'NUMBER', value: num };
  }

  readOperatorOrWord() {
    const start = this.pos;
    this.pos++; // skip '-'
    while (this.pos < this.len && /[a-zA-Z0-9_]/.test(this.input[this.pos])) {
      this.pos++;
    }
    const word = this.input.slice(start, this.pos).toLowerCase();

    if (word === '-and') return { type: 'LOGICAL_AND', value: 'AND' };
    if (word === '-or') return { type: 'LOGICAL_OR', value: 'OR' };
    if (word === '-not') return { type: 'LOGICAL_NOT', value: 'NOT' };

    const validOps = [
      '-eq', '-ne', '-gt', '-ge', '-lt', '-le',
      '-like', '-notlike', '-contains', '-notcontains',
      '-in', '-notin'
    ];
    if (validOps.includes(word)) {
      return { type: 'COMPARISON_OP', value: word };
    }

    throw new SyntaxError(`Unknown operator: '${word}'`);
  }

  readIdentifierOrKeyword() {
    const start = this.pos;
    while (this.pos < this.len && /[a-zA-Z0-9_$.]/.test(this.input[this.pos])) {
      this.pos++;
    }
    const raw = this.input.slice(start, this.pos);
    const lower = raw.toLowerCase();

    if (lower === 'and') return { type: 'LOGICAL_AND', value: 'AND' };
    if (lower === 'or') return { type: 'LOGICAL_OR', value: 'OR' };
    if (lower === 'not') return { type: 'LOGICAL_NOT', value: 'NOT' };
    if (lower === 'true' || lower === '$true') return { type: 'BOOLEAN', value: true };
    if (lower === 'false' || lower === '$false') return { type: 'BOOLEAN', value: false };
    if (lower === 'null' || lower === '$null') return { type: 'NULL', value: null };

    let cleanProp = raw;
    if (cleanProp.toLowerCase().startsWith('device.')) {
      cleanProp = cleanProp.slice(7);
    }
    return { type: 'PROPERTY', raw, clean: cleanProp };
  }
}

export class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek() {
    return this.tokens[this.pos] || { type: 'EOF', value: null };
  }

  consume(type) {
    const token = this.peek();
    if (type && token.type !== type) {
      throw new SyntaxError(`Expected token '${type}' but found '${token.type}' (${token.value || token.raw || ''}) at index ${this.pos}`);
    }
    this.pos++;
    return token;
  }

  parse() {
    const ast = this.parseOr();
    if (this.peek().type !== 'EOF') {
      const extra = this.peek();
      throw new SyntaxError(`Unexpected token after expression: '${extra.value || extra.raw}'`);
    }
    return ast;
  }

  parseOr() {
    let left = this.parseAnd();
    while (this.peek().type === 'LOGICAL_OR') {
      this.consume('LOGICAL_OR');
      const right = this.parseAnd();
      left = {
        type: 'LogicalExpression',
        operator: 'OR',
        left,
        right
      };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseNot();
    while (this.peek().type === 'LOGICAL_AND') {
      this.consume('LOGICAL_AND');
      const right = this.parseNot();
      left = {
        type: 'LogicalExpression',
        operator: 'AND',
        left,
        right
      };
    }
    return left;
  }

  parseNot() {
    if (this.peek().type === 'LOGICAL_NOT') {
      this.consume('LOGICAL_NOT');
      const argument = this.parseNot();
      return {
        type: 'UnaryExpression',
        operator: 'NOT',
        argument
      };
    }
    return this.parsePrimary();
  }

  parsePrimary() {
    const token = this.peek();

    if (token.type === 'LPAREN') {
      this.consume('LPAREN');
      const expr = this.parseOr();
      this.consume('RPAREN');
      return expr;
    }

    if (token.type === 'PROPERTY') {
      return this.parseComparison();
    }

    throw new SyntaxError(`Expected property identifier or '(' but found '${token.type}' (${token.value || token.raw || ''})`);
  }

  parseComparison() {
    const propToken = this.consume('PROPERTY');
    const opToken = this.consume('COMPARISON_OP');
    const value = this.parseValue();

    return {
      type: 'BinaryExpression',
      operator: opToken.value.toLowerCase(),
      property: propToken.clean,
      rawProperty: propToken.raw,
      value
    };
  }

  parseValue() {
    const token = this.peek();

    if (token.type === 'STRING' || token.type === 'NUMBER' || token.type === 'BOOLEAN' || token.type === 'NULL') {
      this.consume();
      return token.value;
    }

    if (token.type === 'LBRACKET' || token.type === 'LPAREN') {
      return this.parseArray();
    }

    throw new SyntaxError(`Expected literal value or array, but found '${token.type}' (${token.value || token.raw || ''})`);
  }

  parseArray() {
    const isBracket = this.peek().type === 'LBRACKET';
    this.consume(isBracket ? 'LBRACKET' : 'LPAREN');
    const elements = [];

    const closeType = isBracket ? 'RBRACKET' : 'RPAREN';
    while (this.peek().type !== closeType && this.peek().type !== 'EOF') {
      const valToken = this.peek();
      if (valToken.type === 'STRING' || valToken.type === 'NUMBER' || valToken.type === 'BOOLEAN' || valToken.type === 'NULL') {
        elements.push(this.consume().value);
      } else {
        throw new SyntaxError(`Array elements must be literal values, found '${valToken.type}'`);
      }

      if (this.peek().type === 'COMMA') {
        this.consume('COMMA');
      } else {
        break;
      }
    }

    this.consume(closeType);
    return elements;
  }
}

export function wildcardToRegExp(pattern) {
  const cached = regexCache.get(pattern);
  if (cached) return cached;

  const str = String(pattern);
  // Escape regex special chars except * and ?
  const escaped = str.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const converted = '^' + escaped.replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
  const rx = new RegExp(converted, 'i');

  if (regexCache.size > 1000) regexCache.clear();
  regexCache.set(pattern, rx);
  return rx;
}

export function normalizeDeviceContext(device, snapshot = null, installedSoftware = []) {
  if (!device || typeof device !== 'object') return {};

  let tags = [];
  if (Array.isArray(device.tags)) {
    tags = device.tags;
  } else if (Array.isArray(device.Tags)) {
    tags = device.Tags;
  } else if (typeof device.tags_json === 'string') {
    try {
      const parsed = JSON.parse(device.tags_json);
      if (Array.isArray(parsed)) tags = parsed;
    } catch {
      tags = [];
    }
  }

  let apps = [];
  if (Array.isArray(installedSoftware) && installedSoftware.length > 0) {
    apps = installedSoftware.map(s => (typeof s === 'string' ? s : (s.winget_id || s.name || ''))).filter(Boolean);
  } else if (Array.isArray(device.InstalledApps)) {
    apps = device.InstalledApps;
  } else if (Array.isArray(device.installed_apps)) {
    apps = device.installed_apps;
  }

  const storageFree = snapshot && typeof snapshot.disk_free_gb === 'number'
    ? snapshot.disk_free_gb
    : (typeof device.StorageFree_GB === 'number' ? device.StorageFree_GB :
      (typeof device.disk_free_gb === 'number' ? device.disk_free_gb : 0));

  const totalRamGb = device.TotalRAM_GB !== undefined && device.TotalRAM_GB !== null
    ? Number(device.TotalRAM_GB)
    : (device.total_ram_gb !== undefined && device.total_ram_gb !== null
      ? Number(device.total_ram_gb)
      : (device.total_ram_bytes ? Number(device.total_ram_bytes) / 1073741824.0 : 0));

  const batteryPercent = device.BatteryPercent !== undefined
    ? device.BatteryPercent
    : (device.battery_percent !== undefined ? device.battery_percent : null);

  const context = {
    hostname: device.Hostname !== undefined ? device.Hostname : device.hostname,
    friendly_name: device.FriendlyName !== undefined ? device.FriendlyName : device.friendly_name,
    total_ram_gb: totalRamGb,
    os_version: device.OSVersion !== undefined ? device.OSVersion : device.os_version,
    os_name: device.OSName !== undefined ? device.OSName : device.os_name,
    os_build: device.OSBuild !== undefined ? device.OSBuild : device.os_build,
    gpu_name: device.GPU !== undefined ? device.GPU : (device.gpu_name !== undefined ? device.gpu_name : null),
    has_battery: device.HasBattery !== undefined ? Boolean(device.HasBattery) : Boolean(device.has_battery),
    battery_percent: batteryPercent,
    storage_free_gb: Number(storageFree),
    tpm_enabled: device.TPMEnabled !== undefined ? Boolean(device.TPMEnabled) : Boolean(device.tpm_enabled),
    tpm_version: device.TPMVersion !== undefined ? device.TPMVersion : device.tpm_version,
    secure_boot_enabled: device.SecureBoot !== undefined ? Boolean(device.SecureBoot) : Boolean(device.secure_boot_enabled),
    bitlocker_status: device.BitLocker !== undefined ? device.BitLocker : (device.bitlocker_status || 'Disabled'),
    assigned_group: device.Group !== undefined ? device.Group : (device.assigned_group || ''),
    tags: tags.map(t => String(t)),
    status: device.Status !== undefined ? device.Status : (device.status || 'offline'),
    connection_route: device.Route !== undefined ? device.Route : (device.connection_route || 'Unknown'),
    installed_apps: apps
  };

  // Also retain raw fields for direct property lookup
  for (const [key, val] of Object.entries(device)) {
    if (!context.hasOwnProperty(key)) {
      context[key] = val;
    }
  }

  return context;
}

export function resolveProperty(context, rawProp) {
  if (!context || typeof context !== 'object') return null;
  const clean = rawProp.toLowerCase().replace(/^device\./, '');
  const mappedKey = PROPERTY_MAP[clean] || clean;

  if (context.hasOwnProperty(mappedKey) && context[mappedKey] !== undefined) {
    return context[mappedKey];
  }

  for (const key of Object.keys(context)) {
    if (key.toLowerCase() === clean || key.toLowerCase() === mappedKey) {
      return context[key];
    }
  }

  return null;
}

export function evaluateComparison(operator, leftVal, rightVal) {
  // If leftVal is null/undefined or property does not exist
  if (leftVal === null || leftVal === undefined) {
    if (operator === '-eq') {
      return rightVal === null || rightVal === undefined;
    }
    if (operator === '-ne') {
      return rightVal !== null && rightVal !== undefined;
    }
    return false;
  }

  switch (operator) {
    case '-eq': {
      if (rightVal === null || rightVal === undefined) return false;
      if (typeof leftVal === 'boolean' || typeof rightVal === 'boolean') {
        return Boolean(leftVal) === Boolean(rightVal);
      }
      if (typeof leftVal === 'number' || typeof rightVal === 'number') {
        const l = Number(leftVal);
        const r = Number(rightVal);
        return !isNaN(l) && !isNaN(r) && l === r;
      }
      return String(leftVal).toLowerCase() === String(rightVal).toLowerCase();
    }
    case '-ne':
      return !evaluateComparison('-eq', leftVal, rightVal);

    case '-gt': {
      const l = Number(leftVal);
      const r = Number(rightVal);
      return !isNaN(l) && !isNaN(r) && l > r;
    }
    case '-ge': {
      const l = Number(leftVal);
      const r = Number(rightVal);
      return !isNaN(l) && !isNaN(r) && l >= r;
    }
    case '-lt': {
      const l = Number(leftVal);
      const r = Number(rightVal);
      return !isNaN(l) && !isNaN(r) && l < r;
    }
    case '-le': {
      const l = Number(leftVal);
      const r = Number(rightVal);
      return !isNaN(l) && !isNaN(r) && l <= r;
    }

    case '-like': {
      const rx = wildcardToRegExp(rightVal);
      return rx.test(String(leftVal));
    }
    case '-notlike':
      return !evaluateComparison('-like', leftVal, rightVal);

    case '-contains': {
      if (Array.isArray(leftVal)) {
        const target = String(rightVal).toLowerCase();
        return leftVal.some(item => String(item).toLowerCase() === target);
      }
      if (typeof leftVal === 'string') {
        return leftVal.toLowerCase().includes(String(rightVal).toLowerCase());
      }
      return false;
    }
    case '-notcontains':
      return !evaluateComparison('-contains', leftVal, rightVal);

    case '-in': {
      if (Array.isArray(rightVal)) {
        const target = String(leftVal).toLowerCase();
        return rightVal.some(item => String(item).toLowerCase() === target);
      }
      return String(leftVal).toLowerCase() === String(rightVal).toLowerCase();
    }
    case '-notin':
      return !evaluateComparison('-in', leftVal, rightVal);

    default:
      return false;
  }
}

export function evaluateNode(node, context) {
  if (!node) return false;

  switch (node.type) {
    case 'LogicalExpression': {
      if (node.operator === 'AND') {
        return evaluateNode(node.left, context) && evaluateNode(node.right, context);
      }
      if (node.operator === 'OR') {
        return evaluateNode(node.left, context) || evaluateNode(node.right, context);
      }
      return false;
    }
    case 'UnaryExpression': {
      if (node.operator === 'NOT') {
        return !evaluateNode(node.argument, context);
      }
      return false;
    }
    case 'BinaryExpression': {
      const leftVal = resolveProperty(context, node.property);
      return evaluateComparison(node.operator, leftVal, node.value);
    }
    default:
      return false;
  }
}

export function parseRule(ruleSyntax) {
  if (!ruleSyntax || typeof ruleSyntax !== 'string' || !ruleSyntax.trim()) {
    return { valid: false, error: 'Rule syntax cannot be empty' };
  }

  const cached = astCache.get(ruleSyntax);
  if (cached) return { valid: true, ast: cached };

  try {
    const lexer = new Lexer(ruleSyntax);
    const tokens = lexer.tokenize();
    const parser = new Parser(tokens);
    const ast = parser.parse();

    if (astCache.size > 500) astCache.clear();
    astCache.set(ruleSyntax, ast);
    return { valid: true, ast };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

export function evaluateRule(ruleSyntax, deviceContext) {
  if (!ruleSyntax || typeof ruleSyntax !== 'string' || !ruleSyntax.trim()) return false;
  try {
    const parsed = parseRule(ruleSyntax);
    if (!parsed.valid || !parsed.ast) return false;
    const context = normalizeDeviceContext(deviceContext);
    return Boolean(evaluateNode(parsed.ast, context));
  } catch {
    return false;
  }
}

export const dynamicGroupsService = {
  parseRule(ruleSyntax) {
    const res = parseRule(ruleSyntax);
    if (!res.valid) {
      throw new SyntaxError(res.error);
    }
    return res.ast;
  },

  validateRule(ruleSyntax) {
    return parseRule(ruleSyntax);
  },

  evaluateDevice(device, ruleSyntax, snapshot = null, installedSoftware = []) {
    try {
      const parsed = typeof ruleSyntax === 'string' ? parseRule(ruleSyntax) : { valid: true, ast: ruleSyntax };
      if (!parsed.valid || !parsed.ast) return false;
      const context = normalizeDeviceContext(device, snapshot, installedSoftware);
      return Boolean(evaluateNode(parsed.ast, context));
    } catch {
      return false;
    }
  },

  reevaluateDeviceMemberships(db, deviceId, snapshot = null, installedSoftware = []) {
    const deviceStmt = db.prepare('SELECT * FROM devices WHERE id = ?');
    const device = deviceStmt.get(deviceId);
    if (!device) return [];

    const groupsStmt = db.prepare('SELECT id, name, rule_syntax FROM dynamic_groups WHERE is_dynamic = 1 ORDER BY priority ASC');
    const groups = groupsStmt.all();

    const context = normalizeDeviceContext(device, snapshot, installedSoftware);
    const matchingGroupIds = [];

    for (const grp of groups) {
      try {
        const parsed = parseRule(grp.rule_syntax);
        if (parsed.valid && evaluateNode(parsed.ast, context)) {
          matchingGroupIds.push(grp.id);
        }
      } catch {
        // Skip invalid group rule syntax safely
      }
    }

    const deleteDynamicStmt = db.prepare('DELETE FROM group_memberships WHERE device_id = ? AND manually_assigned = 0');
    const insertStmt = db.prepare(`
      INSERT INTO group_memberships (group_id, device_id, is_dynamic_match, manually_assigned, evaluated_at)
      VALUES (?, ?, 1, 0, DATETIME('now'))
      ON CONFLICT(group_id, device_id) DO UPDATE SET
        is_dynamic_match = 1,
        evaluated_at = DATETIME('now')
    `);

    db.exec('BEGIN TRANSACTION;');
    try {
      deleteDynamicStmt.run(deviceId);
      for (const gid of matchingGroupIds) {
        insertStmt.run(gid, deviceId);
      }
      db.exec('COMMIT;');
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }

    return matchingGroupIds;
  },

  evaluateRuleAgainstAllDevices(db, ruleSyntax) {
    const validation = this.validateRule(ruleSyntax);
    if (!validation.valid) {
      return { valid: false, error: validation.error, matched_devices: [], total_matches: 0 };
    }

    const ast = validation.ast;
    const devices = db.prepare('SELECT * FROM devices').all();

    const matchedDevices = [];
    for (const dev of devices) {
      const context = normalizeDeviceContext(dev);
      if (evaluateNode(ast, context)) {
        matchedDevices.push({
          id: dev.id,
          hostname: dev.hostname,
          friendly_name: dev.friendly_name,
          status: dev.status
        });
      }
    }

    return {
      valid: true,
      total_matches: matchedDevices.length,
      matched_devices: matchedDevices
    };
  }
};

export default dynamicGroupsService;
