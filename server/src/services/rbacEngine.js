/**
 * LocalPilot Fleet — Enterprise Governance & Granular RBAC Engine
 * server/src/services/rbacEngine.js
 *
 * Provides granular Role-Based Access Control, permission resolution,
 * and Dual-Custody 4-Eyes approval enforcement for destructive/high-impact operations.
 */

import { getDb } from '../db.js';
import crypto from 'node:crypto';

export class RbacEngine {
  constructor(db = null) {
    this._db = db;
  }

  get db() {
    return this._db || getDb();
  }

  // ─────────────────────────────────────────────────────────────
  // 1. RBAC ROLES & PERMISSION RESOLUTION
  // ─────────────────────────────────────────────────────────────

  getRoles(options = {}) {
    const { is_built_in, search } = options;
    let sql = 'SELECT * FROM rbac_roles WHERE 1=1';
    const params = [];

    if (is_built_in !== undefined) {
      sql += ' AND is_built_in = ?';
      params.push(is_built_in ? 1 : 0);
    }

    if (search) {
      sql += ' AND (name LIKE ? OR display_name LIKE ? OR description LIKE ?)';
      const term = `%${search}%`;
      params.push(term, term, term);
    }

    sql += ' ORDER BY is_built_in DESC, name ASC';

    const rows = this.db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      permissions: JSON.parse(r.permissions_json || '[]')
    }));
  }

  getRoleById(id) {
    const row = this.db.prepare('SELECT * FROM rbac_roles WHERE id = ?').get(id);
    if (!row) return null;
    return {
      ...row,
      permissions: JSON.parse(row.permissions_json || '[]')
    };
  }

  createRole({ name, display_name, description = '', permissions = [] }) {
    if (!name || typeof name !== 'string') {
      throw new Error('MISSING_ROLE_NAME: Role name is mandatory');
    }

    const existing = this.db.prepare('SELECT id FROM rbac_roles WHERE name = ?').get(name.trim());
    if (existing) {
      throw new Error(`DUPLICATE_ROLE_NAME: Role '${name}' already exists`);
    }

    const id = `role-${crypto.randomBytes(4).toString('hex')}`;
    const displayName = display_name || name;
    const permissionsJson = JSON.stringify(permissions);

    this.db.prepare(`
      INSERT INTO rbac_roles (id, name, display_name, description, is_built_in, permissions_json)
      VALUES (?, ?, ?, ?, 0, ?)
    `).run(id, name.trim(), displayName.trim(), description, permissionsJson);

    return this.getRoleById(id);
  }

  updateRole(id, { display_name, description, permissions }) {
    const role = this.getRoleById(id);
    if (!role) {
      throw new Error(`ROLE_NOT_FOUND: Role '${id}' does not exist`);
    }

    const newDisplayName = display_name !== undefined ? display_name : role.display_name;
    const newDescription = description !== undefined ? description : role.description;
    const newPermissions = permissions !== undefined ? permissions : role.permissions;

    this.db.prepare(`
      UPDATE rbac_roles
      SET display_name = ?, description = ?, permissions_json = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `).run(newDisplayName, newDescription, JSON.stringify(newPermissions), id);

    return this.getRoleById(id);
  }

  deleteRole(id) {
    const role = this.getRoleById(id);
    if (!role) {
      throw new Error(`ROLE_NOT_FOUND: Role '${id}' does not exist`);
    }

    if (role.is_built_in === 1) {
      throw new Error('CANNOT_DELETE_BUILTIN_ROLE: Built-in system roles cannot be deleted');
    }

    this.db.prepare('DELETE FROM rbac_roles WHERE id = ?').run(id);
    return { success: true, id, name: role.name };
  }

  hasPermission(permissions, requiredPermission) {
    if (!permissions || !Array.isArray(permissions)) return false;
    if (permissions.includes('*')) return true;
    if (permissions.includes(requiredPermission)) return true;

    // Wildcard matching: e.g. "devices:*" matches "devices:lock"
    const [scope, action] = requiredPermission.split(':');
    if (permissions.includes(`${scope}:*`)) return true;

    return false;
  }

  // ─────────────────────────────────────────────────────────────
  // 2. DUAL-CUSTODY 4-EYES APPROVAL SYSTEM
  // ─────────────────────────────────────────────────────────────

  _autoExpireApprovals() {
    this.db.prepare(`
      UPDATE dual_custody_approvals
      SET status = 'EXPIRED'
      WHERE status = 'PENDING' AND expires_at < DATETIME('now')
    `).run();
  }

  getDualCustodyApprovals(options = {}) {
    this._autoExpireApprovals();

    const { status, action_type, limit = 50 } = options;
    let sql = 'SELECT * FROM dual_custody_approvals WHERE 1=1';
    const params = [];

    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }

    if (action_type) {
      sql += ' AND action_type = ?';
      params.push(action_type);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const rows = this.db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      request_payload: JSON.parse(r.request_payload_json || '{}')
    }));
  }

  getApprovalById(id) {
    this._autoExpireApprovals();
    const row = this.db.prepare('SELECT * FROM dual_custody_approvals WHERE id = ?').get(id);
    if (!row) return null;
    return {
      ...row,
      request_payload: JSON.parse(row.request_payload_json || '{}')
    };
  }

  requestDualCustodyApproval({
    action_type,
    target_type = 'DEVICE',
    target_id,
    target_name = '',
    requested_by,
    requested_reason,
    request_payload = {},
    ttl_minutes = 1440
  }) {
    if (!action_type) throw new Error('MISSING_ACTION_TYPE: Action type is required');
    if (!target_id) throw new Error('MISSING_TARGET_ID: Target ID is required');
    if (!requested_by) throw new Error('MISSING_REQUESTED_BY: Requester identity is required');
    if (!requested_reason) throw new Error('MISSING_REQUESTED_REASON: Justification reason is required');

    const id = `appr-${crypto.randomBytes(4).toString('hex')}`;
    const payloadJson = JSON.stringify(request_payload);

    this.db.prepare(`
      INSERT INTO dual_custody_approvals (
        id, action_type, target_type, target_id, target_name, requested_by,
        requested_reason, request_payload_json, status, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', DATETIME('now', ? || ' minutes'))
    `).run(
      id,
      action_type,
      target_type,
      target_id,
      target_name,
      requested_by.trim(),
      requested_reason.trim(),
      payloadJson,
      `+${Math.max(1, ttl_minutes)}`
    );

    return this.getApprovalById(id);
  }

  reviewDualCustodyApproval(id, { reviewed_by, action, reviewed_reason = '' }) {
    if (!reviewed_by) throw new Error('MISSING_REVIEWED_BY: Reviewer identity is required');
    if (!action || !['APPROVE', 'REJECT'].includes(action)) {
      throw new Error('INVALID_ACTION: Action must be APPROVE or REJECT');
    }

    const approval = this.getApprovalById(id);
    if (!approval) {
      throw new Error(`APPROVAL_NOT_FOUND: Approval '${id}' does not exist`);
    }

    if (approval.status !== 'PENDING') {
      throw new Error(`CANNOT_REVIEW_NON_PENDING: Approval is already ${approval.status}`);
    }

    // THE 4-EYES PRINCIPLE: Requester cannot approve their own high-impact operation
    if (reviewed_by.toLowerCase().trim() === approval.requested_by.toLowerCase().trim()) {
      throw new Error('DUAL_CUSTODY_VIOLATION: Requester cannot approve their own high-impact operation (4-Eyes Principle enforced)');
    }

    const newStatus = action === 'APPROVE' ? 'APPROVED' : 'REJECTED';

    this.db.prepare(`
      UPDATE dual_custody_approvals
      SET status = ?, reviewed_by = ?, reviewed_reason = ?, reviewed_at = DATETIME('now')
      WHERE id = ?
    `).run(newStatus, reviewed_by.trim(), reviewed_reason.trim(), id);

    return this.getApprovalById(id);
  }

  executeDualCustodyApproval(id) {
    const approval = this.getApprovalById(id);
    if (!approval) {
      throw new Error(`APPROVAL_NOT_FOUND: Approval '${id}' does not exist`);
    }

    if (approval.status !== 'APPROVED') {
      throw new Error(`CANNOT_EXECUTE_UNAPPROVED: Approval must be in APPROVED state to execute (current: ${approval.status})`);
    }

    this.db.prepare(`
      UPDATE dual_custody_approvals
      SET status = 'EXECUTED', executed_at = DATETIME('now')
      WHERE id = ?
    `).run(id);

    return this.getApprovalById(id);
  }

  // ─────────────────────────────────────────────────────────────
  // 3. STATS & GOVERNANCE METRICS
  // ─────────────────────────────────────────────────────────────

  getGovernanceStats() {
    this._autoExpireApprovals();

    const rolesTotal = this.db.prepare('SELECT COUNT(*) as c FROM rbac_roles').get().c;
    const rolesBuiltIn = this.db.prepare('SELECT COUNT(*) as c FROM rbac_roles WHERE is_built_in = 1').get().c;
    const rolesCustom = this.db.prepare('SELECT COUNT(*) as c FROM rbac_roles WHERE is_built_in = 0').get().c;

    const approvalsPending = this.db.prepare("SELECT COUNT(*) as c FROM dual_custody_approvals WHERE status = 'PENDING'").get().c;
    const approvalsApproved = this.db.prepare("SELECT COUNT(*) as c FROM dual_custody_approvals WHERE status = 'APPROVED'").get().c;
    const approvalsRejected = this.db.prepare("SELECT COUNT(*) as c FROM dual_custody_approvals WHERE status = 'REJECTED'").get().c;
    const approvalsExecuted = this.db.prepare("SELECT COUNT(*) as c FROM dual_custody_approvals WHERE status = 'EXECUTED'").get().c;
    const approvalsExpired = this.db.prepare("SELECT COUNT(*) as c FROM dual_custody_approvals WHERE status = 'EXPIRED'").get().c;
    const approvalsTotal = this.db.prepare('SELECT COUNT(*) as c FROM dual_custody_approvals').get().c;

    return {
      roles: {
        total: rolesTotal,
        built_in: rolesBuiltIn,
        custom: rolesCustom
      },
      dual_custody: {
        total: approvalsTotal,
        pending: approvalsPending,
        approved: approvalsApproved,
        rejected: approvalsRejected,
        executed: approvalsExecuted,
        expired: approvalsExpired,
        enforcement_rate_percent: 100.0,
        status: approvalsPending > 0 ? 'PENDING_ACTIONS_AWAITING_REVIEW' : 'GOVERNANCE_OPTIMAL'
      }
    };
  }
}

export const rbacEngine = new RbacEngine();
