/**
 * LocalPilot Fleet — Dual-Tier Authentication Middleware
 * server/src/utils/auth.js
 */

import crypto from 'node:crypto';
import { getDb } from '../db.js';
import { sendJson } from './router.js';

let configuredFleetKey = process.env.FLEET_KEY || 'localpilot-secret-key-2026';

export function setFleetKey(key) {
  if (key) configuredFleetKey = key;
}

export function getFleetKey() {
  return configuredFleetKey;
}

export function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function generateNodeToken() {
  const raw = `lp_node_${crypto.randomBytes(24).toString('hex')}`;
  const hash = hashToken(raw);
  return { token: raw, hash };
}

export function requireFleetKey(req, res) {
  const clientKey = req.headers['x-fleet-key'];
  if (!clientKey) {
    sendJson(res, 401, { error: 'UNAUTHORIZED', message: 'Missing X-Fleet-Key header' });
    return false;
  }

  // Check in-memory key first
  if (clientKey === configuredFleetKey) return true;

  // Fallback to database setting
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM fleet_settings WHERE key = 'fleet_enrollment_key'").get();
    if (row && row.value === clientKey) return true;
  } catch (err) {
    // ignore db lookup failure
  }

  sendJson(res, 401, { error: 'INVALID_FLEET_KEY', message: 'The provided X-Fleet-Key is invalid' });
  return false;
}

export function requireNodeToken(req, res) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    sendJson(res, 401, { error: 'UNAUTHORIZED', message: 'Missing or malformed Bearer Authorization header' });
    return false;
  }

  const rawToken = authHeader.slice(7).trim();
  if (!rawToken) {
    sendJson(res, 401, { error: 'INVALID_NODE_TOKEN', message: 'Empty Bearer token' });
    return false;
  }

  const tokenHash = hashToken(rawToken);
  try {
    const db = getDb();
    const device = db.prepare('SELECT * FROM devices WHERE node_token_hash = ?').get(tokenHash);
    if (!device) {
      sendJson(res, 401, { error: 'INVALID_NODE_TOKEN', message: 'Device token unrecognized or revoked' });
      return false;
    }
    req.device = device;
    return true;
  } catch (err) {
    sendJson(res, 500, { error: 'AUTH_ERROR', message: err.message });
    return false;
  }
}

export function requireFleetKeyOrNodeToken(req, res, targetDeviceId = null) {
  if (req.headers['x-fleet-key']) {
    return requireFleetKey(req, res);
  }

  if (req.headers['authorization']) {
    const authenticated = requireNodeToken(req, res);
    if (!authenticated) return false;

    if (targetDeviceId && req.device && req.device.id !== targetDeviceId) {
      sendJson(res, 403, {
        error: 'FORBIDDEN',
        message: 'Node token cannot access policy or data of another device'
      });
      return false;
    }
    return true;
  }

  sendJson(res, 401, { error: 'UNAUTHORIZED', message: 'Missing authorization credentials' });
  return false;
}
