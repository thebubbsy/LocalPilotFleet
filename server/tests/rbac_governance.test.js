import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { initDb, closeDb } from '../src/db.js';
import { rbacEngine } from '../src/services/rbacEngine.js';
import { siemForwarderEngine } from '../src/services/siemForwarderEngine.js';

describe('Enterprise Governance, Granular RBAC, Dual-Custody 4-Eyes & RFC 5424 SIEM (Dimension 6)', () => {
  let db;

  before(() => {
    db = initDb(':memory:', { seed: true });
    rbacEngine._db = db;
    siemForwarderEngine._db = db;
  });

  after(() => {
    closeDb();
  });

  // 1. RBAC STATS
  it('RBAC-01: should return baseline RBAC & governance stats with built-in roles', () => {
    const stats = rbacEngine.getGovernanceStats();
    assert.ok(stats.roles.total >= 4, 'Should have at least 4 built-in roles');
    assert.strictEqual(stats.roles.built_in >= 4, true);
    assert.ok(stats.dual_custody.total >= 1, 'Should have seed dual custody approval');
    assert.strictEqual(stats.dual_custody.enforcement_rate_percent, 100.0);
  });

  // 2. LIST ROLES
  it('RBAC-02: should list all roles including built-in roles with parsed permissions', () => {
    const roles = rbacEngine.getRoles();
    assert.ok(roles.length >= 4);
    const globalAdmin = roles.find(r => r.name === 'Global Administrator');
    assert.ok(globalAdmin);
    assert.strictEqual(globalAdmin.is_built_in, 1);
    assert.deepStrictEqual(globalAdmin.permissions, ['*']);
  });

  // 3. GET SINGLE ROLE
  it('RBAC-03: should retrieve a single role by ID with permissions array', () => {
    const role = rbacEngine.getRoleById('role-security-operator');
    assert.ok(role);
    assert.strictEqual(role.name, 'Security Operator');
    assert.ok(Array.isArray(role.permissions));
    assert.ok(role.permissions.includes('devices:lock'));
    assert.ok(role.permissions.includes('devices:isolate'));
  });

  // 4. CREATE CUSTOM ROLE
  it('RBAC-04: should create a new custom RBAC role with granular permissions', () => {
    const newRole = rbacEngine.createRole({
      name: 'Tier-2 Desktop Support',
      display_name: 'Tier-2 Desktop Support Lead',
      description: 'Handles workstation troubleshooting and remote restart',
      permissions: ['devices:read', 'devices:reboot', 'diagnostics:read']
    });

    assert.ok(newRole);
    assert.strictEqual(newRole.name, 'Tier-2 Desktop Support');
    assert.strictEqual(newRole.is_built_in, 0);
    assert.deepStrictEqual(newRole.permissions, ['devices:read', 'devices:reboot', 'diagnostics:read']);
  });

  // 5. REJECT DUPLICATE OR MISSING NAME
  it('RBAC-05: should reject creating role with duplicate or missing name', () => {
    assert.throws(() => {
      rbacEngine.createRole({ name: '' });
    }, /MISSING_ROLE_NAME/);

    assert.throws(() => {
      rbacEngine.createRole({ name: 'Global Administrator' });
    }, /DUPLICATE_ROLE_NAME/);
  });

  // 6. UPDATE ROLE
  it('RBAC-06: should update an existing role permissions and display name', () => {
    const roles = rbacEngine.getRoles();
    const customRole = roles.find(r => r.name === 'Tier-2 Desktop Support');
    assert.ok(customRole);

    const updated = rbacEngine.updateRole(customRole.id, {
      display_name: 'Senior Tier-2 Desktop Specialist',
      permissions: ['devices:read', 'devices:reboot', 'diagnostics:read', 'commands:execute_read_only']
    });

    assert.strictEqual(updated.display_name, 'Senior Tier-2 Desktop Specialist');
    assert.ok(updated.permissions.includes('commands:execute_read_only'));
  });

  // 7. PREVENT DELETION OF BUILT-IN ROLES
  it('RBAC-07: should prevent deletion of built-in system roles', () => {
    assert.throws(() => {
      rbacEngine.deleteRole('role-global-admin');
    }, /CANNOT_DELETE_BUILTIN_ROLE/);
  });

  // 8. DELETE CUSTOM ROLE
  it('RBAC-08: should allow deletion of custom roles', () => {
    const tempRole = rbacEngine.createRole({
      name: 'Temporary Role for Audit',
      permissions: ['audit:read']
    });

    const res = rbacEngine.deleteRole(tempRole.id);
    assert.strictEqual(res.success, true);
    assert.strictEqual(rbacEngine.getRoleById(tempRole.id), null);
  });

  // 9. PERMISSION EVALUATION & WILDCARDS
  it('RBAC-09: should accurately evaluate permission checks including wildcard patterns (*, devices:*)', () => {
    assert.strictEqual(rbacEngine.hasPermission(['*'], 'any:permission'), true);
    assert.strictEqual(rbacEngine.hasPermission(['devices:*'], 'devices:lock'), true);
    assert.strictEqual(rbacEngine.hasPermission(['devices:*'], 'devices:isolate'), true);
    assert.strictEqual(rbacEngine.hasPermission(['devices:*'], 'compliance:write'), false);
    assert.strictEqual(rbacEngine.hasPermission(['devices:read', 'devices:reboot'], 'devices:reboot'), true);
    assert.strictEqual(rbacEngine.hasPermission(['devices:read', 'devices:reboot'], 'devices:wipe'), false);
  });

  // 10. LIST DUAL CUSTODY APPROVALS
  it('RBAC-10: should list dual custody approvals including seed pending approval', () => {
    const approvals = rbacEngine.getDualCustodyApprovals();
    assert.ok(approvals.length >= 1);
    const appr = approvals.find(a => a.id === 'appr-01');
    assert.ok(appr);
    assert.strictEqual(appr.action_type, 'REMOTE_WIPE');
    assert.strictEqual(appr.status, 'PENDING');
  });

  // 11. REQUEST NEW DUAL CUSTODY APPROVAL
  it('RBAC-11: should request a new dual custody approval for destructive action (REMOTE_WIPE)', () => {
    const req = rbacEngine.requestDualCustodyApproval({
      action_type: 'REMOTE_WIPE',
      target_type: 'DEVICE',
      target_id: 'dev-daddy-pc',
      target_name: "Dad's Workstation",
      requested_by: 'alice.admin@localpilot.corp',
      requested_reason: 'Zero-Trust emergency factory reset after device loss reported',
      request_payload: { wipeType: 'FACTORY_RESET', bitlockerRevoke: true },
      ttl_minutes: 60
    });

    assert.ok(req);
    assert.strictEqual(req.status, 'PENDING');
    assert.strictEqual(req.requested_by, 'alice.admin@localpilot.corp');
    assert.strictEqual(req.request_payload.bitlockerRevoke, true);
  });

  // 12. 4-EYES ENFORCEMENT: CANNOT APPROVE OWN REQUEST
  it('RBAC-12: should ENFORCE 4-EYES PRINCIPLE: reject when requester tries to approve own request', () => {
    const approvals = rbacEngine.getDualCustodyApprovals({ status: 'PENDING' });
    const aliceAppr = approvals.find(a => a.requested_by === 'alice.admin@localpilot.corp');
    assert.ok(aliceAppr);

    assert.throws(() => {
      rbacEngine.reviewDualCustodyApproval(aliceAppr.id, {
        reviewed_by: 'alice.admin@localpilot.corp',
        action: 'APPROVE',
        reviewed_reason: 'Self-approving my own wipe request'
      });
    }, /DUAL_CUSTODY_VIOLATION/);
  });

  // 13. APPROVAL BY SECOND ADMINISTRATOR
  it('RBAC-13: should allow second administrator to approve dual custody request', () => {
    const approvals = rbacEngine.getDualCustodyApprovals({ status: 'PENDING' });
    const aliceAppr = approvals.find(a => a.requested_by === 'alice.admin@localpilot.corp');
    assert.ok(aliceAppr);

    const approved = rbacEngine.reviewDualCustodyApproval(aliceAppr.id, {
      reviewed_by: 'charlie.security@localpilot.corp',
      action: 'APPROVE',
      reviewed_reason: 'Verified incident ticket #SEC-9901; remote wipe authorized'
    });

    assert.strictEqual(approved.status, 'APPROVED');
    assert.strictEqual(approved.reviewed_by, 'charlie.security@localpilot.corp');
    assert.ok(approved.reviewed_at);
  });

  // 14. REJECT DUAL CUSTODY REQUEST
  it('RBAC-14: should allow administrator to reject dual custody request', () => {
    const req = rbacEngine.requestDualCustodyApproval({
      action_type: 'DEVICE_DELETE',
      target_type: 'DEVICE',
      target_id: 'dev-livingroom-pc',
      target_name: 'Living Room PC',
      requested_by: 'junior.tech@localpilot.corp',
      requested_reason: 'Accidental device deletion attempt'
    });

    const rejected = rbacEngine.reviewDualCustodyApproval(req.id, {
      reviewed_by: 'senior.admin@localpilot.corp',
      action: 'REJECT',
      reviewed_reason: 'Living Room PC is active in production, deletion rejected'
    });

    assert.strictEqual(rejected.status, 'REJECTED');
    assert.strictEqual(rejected.reviewed_by, 'senior.admin@localpilot.corp');
  });

  // 15. REJECT REVIEW ON ALREADY COMPLETED APPROVAL
  it('RBAC-15: should reject review on already approved, rejected, or expired approval', () => {
    const approvals = rbacEngine.getDualCustodyApprovals({ status: 'REJECTED' });
    const rej = approvals[0];
    assert.ok(rej);

    assert.throws(() => {
      rbacEngine.reviewDualCustodyApproval(rej.id, {
        reviewed_by: 'another.admin@localpilot.corp',
        action: 'APPROVE'
      });
    }, /CANNOT_REVIEW_NON_PENDING/);
  });

  // 16. EXECUTE APPROVED ACTION
  it('RBAC-16: should execute approved dual custody action and transition status to EXECUTED', () => {
    const approvals = rbacEngine.getDualCustodyApprovals({ status: 'APPROVED' });
    const app = approvals[0];
    assert.ok(app);

    const executed = rbacEngine.executeDualCustodyApproval(app.id);
    assert.strictEqual(executed.status, 'EXECUTED');
    assert.ok(executed.executed_at);
  });

  // 17. REJECT EXECUTION OF NON-APPROVED APPROVAL
  it('RBAC-17: should reject execution of non-approved approval', () => {
    const pendingReq = rbacEngine.requestDualCustodyApproval({
      action_type: 'QUARANTINE_FLEET',
      target_type: 'FLEET',
      target_id: 'fleet-all',
      target_name: 'All Devices',
      requested_by: 'operator.dan@localpilot.corp',
      requested_reason: 'Suspected lateral ransomware outbreak'
    });

    assert.throws(() => {
      rbacEngine.executeDualCustodyApproval(pendingReq.id);
    }, /CANNOT_EXECUTE_UNAPPROVED/);
  });

  // 18. RFC 5424 STRICT SYSLOG FORMATTING
  it('RBAC-18: should format strict RFC 5424 Syslog messages with priority, timestamp, structured data', () => {
    const rfcMsg = siemForwarderEngine.formatRfc5424Message({
      facility: 16,
      severity: 2, // Critical
      timestamp: '2026-09-10T00:00:00.000Z',
      hostname: 'DESKTOP-R0H12DJ',
      appName: 'LocalPilotSecurity',
      procId: '4112',
      msgId: 'MALWARE_THREAT',
      structuredData: '[threat@59214 name="Mimikatz" action="BLOCKED"]',
      message: 'Defender blocked LSASS credential harvesting attempt'
    });

    // Priority = 16*8 + 2 = 130
    assert.strictEqual(rfcMsg.startsWith('<130>1 2026-09-10T00:00:00.000Z DESKTOP-R0H12DJ LocalPilotSecurity 4112 MALWARE_THREAT [threat@59214 name="Mimikatz" action="BLOCKED"] Defender blocked LSASS credential harvesting attempt'), true);
  });

  // 19. SIEM FORWARDER CRUD & FORWARD DISPATCH
  it('RBAC-19: should create, test, and forward security events to SIEM forwarders with severity filtering', () => {
    const newForwarder = siemForwarderEngine.createForwarder({
      name: 'Splunk Enterprise HEC Cluster',
      destination_type: 'SPLUNK_HEC',
      host: 'splunk-indexer.localpilot.corp',
      port: 8088,
      auth_token: 'secret-hec-token-998877',
      tls_enabled: 1,
      severity_filter: 'WARNING_AND_ABOVE'
    });

    assert.ok(newForwarder);
    assert.strictEqual(newForwarder.destination_type, 'SPLUNK_HEC');
    assert.strictEqual(newForwarder.tls_enabled, 1);
    assert.strictEqual(newForwarder.auth_token_masked.includes('••••••••8877'), true);

    const testRes = siemForwarderEngine.testForwarderConnection(newForwarder.id);
    assert.strictEqual(testRes.status, 'REACHABLE');
    assert.ok(testRes.rfc5424_sample.includes('<134>1')); // 16*8+6 = 134

    // Dispatch event that matches filter
    const forwardRes = siemForwarderEngine.forwardSecurityEvent({
      event_type: 'ROGUE_PORT_DETECTED',
      severity: 'HIGH',
      hostname: 'DESKTOP-R0H12DJ',
      summary: 'Port 4444 opened by unauthorized process'
    });

    assert.ok(forwardRes.forwarded_count >= 1);
    assert.ok(forwardRes.sample_rfc5424);

    // Filter rejection: LOW event should NOT be forwarded to WARNING_AND_ABOVE target
    const target = siemForwarderEngine.getForwarderById(newForwarder.id);
    const countBefore = target.total_events_forwarded;
    siemForwarderEngine.forwardSecurityEvent({
      event_type: 'INFORMATIONAL_PING',
      severity: 'INFO',
      summary: 'Normal ping'
    }, newForwarder.id);
    const targetAfter = siemForwarderEngine.getForwarderById(newForwarder.id);
    assert.strictEqual(targetAfter.total_events_forwarded, countBefore, 'INFO event filtered out');
  });

  // 20. UPDATE, DELETE & SIEM STATS
  it('RBAC-20: should update and delete SIEM forwarders and track event counters', () => {
    const forwarders = siemForwarderEngine.getForwarders();
    const splunk = forwarders.find(f => f.destination_type === 'SPLUNK_HEC');
    assert.ok(splunk);

    const updated = siemForwarderEngine.updateForwarder(splunk.id, {
      port: 8089,
      is_enabled: 0
    });
    assert.strictEqual(updated.port, 8089);
    assert.strictEqual(updated.is_enabled, 0);

    const stats = siemForwarderEngine.getSiemStats();
    assert.ok(stats.total_forwarders >= 2);
    assert.strictEqual(stats.protocol_standard, 'RFC 5424');

    const delRes = siemForwarderEngine.deleteForwarder(splunk.id);
    assert.strictEqual(delRes.success, true);
    assert.strictEqual(siemForwarderEngine.getForwarderById(splunk.id), null);
  });
});
