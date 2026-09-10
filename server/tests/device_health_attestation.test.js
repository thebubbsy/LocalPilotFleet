/**
 * Iteration 45: Zero-Trust Device Health Attestation (DHA) & Microsegmentation Test Suite
 * Validates hardware root-of-trust, TPM 2.0 PCR measured boot, and dynamic WFP network isolation.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { DeviceHealthAttestationEngine } from '../src/services/deviceHealthAttestationEngine.js';

describe('Iteration 45: Zero-Trust Device Health Attestation & Microsegmentation (device_health_attestation.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-fleet-key-dha-45';
  const TEST_DEVICE_ID = 'dev-dha-test-01';
  let createdPolicyId;
  let createdMspId;

  const router = {
    routes: { GET: [], POST: [], PATCH: [], DELETE: [], PUT: [] },
    get(path, handler) { this.routes.GET.push({ path, handler }); },
    post(path, handler) { this.routes.POST.push({ path, handler }); },
    put(path, handler) { this.routes.PUT.push({ path, handler }); },
    patch(path, handler) { this.routes.PATCH.push({ path, handler }); },
    delete(path, handler) { this.routes.DELETE.push({ path, handler }); }
  };

  function matchRoute(method, urlPath) {
    const list = router.routes[method] || [];
    for (const r of list) {
      if (r.path === urlPath) return { handler: r.handler, params: {} };
      const rParts = r.path.split('/');
      const uParts = urlPath.split('/');
      if (rParts.length === uParts.length) {
        let match = true;
        const params = {};
        for (let i = 0; i < rParts.length; i++) {
          if (rParts[i].startsWith(':')) {
            params[rParts[i].slice(1)] = uParts[i];
          } else if (rParts[i] !== uParts[i]) {
            match = false;
            break;
          }
        }
        if (match) return { handler: r.handler, params };
      }
    }
    return null;
  }

  before(async () => {
    db = initDb(':memory:');
    setFleetKey(TEST_FLEET_KEY);
    registerFleetRoutes(router);
    registerNodeRoutes(router);

    // Ensure sample test device exists
    db.prepare(`
      INSERT OR REPLACE INTO devices (id, hostname, serial_number, os_name, os_version, total_ram_bytes, node_token_hash, agent_version)
      VALUES (?, 'DESKTOP-SECURE-DHA', 'SN-DHA-45001', 'Windows 11 Enterprise', '10.0.26100.1742', 17179869184, 'tokenhash-dha-999', '2.4.0')
    `).run(TEST_DEVICE_ID);

    server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://localhost');
      const route = matchRoute(req.method, url.pathname);
      if (!route) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'NOT_FOUND', message: 'Route not found' }));
        return;
      }

      req.params = route.params;
      req.query = Object.fromEntries(url.searchParams.entries());

      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        if (body) {
          try { req.body = JSON.parse(body); } catch(e) { req.body = {}; }
        } else {
          req.body = {};
        }
        route.handler(req, res);
      });
    });

    await new Promise(resolve => server.listen(0, resolve));
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    if (server) {
      await new Promise(resolve => server.close(resolve));
    }
    closeDb();
  });

  const apiRequest = async (method, path, body = null, headers = {}) => {
    const finalHeaders = {
      'X-Fleet-Key': TEST_FLEET_KEY,
      'Content-Type': 'application/json',
      ...headers
    };
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: finalHeaders,
      body: body ? JSON.stringify(body) : undefined
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, data: json };
  };

  test('DHA-01: GET /api/v1/fleet/dha/stats returns hardware root-of-trust metrics and compliance percent', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/dha/stats');
    assert.equal(status, 200);
    assert.equal(typeof data.totalPolicies, 'number');
    assert.equal(typeof data.complianceRatePercent, 'number');
    assert.equal(data.hardwareRootOfTrustEnforced, true);
    assert.ok(data.attestationAuthority.includes('TPM 2.0'));
  });

  test('DHA-02: GET /api/v1/fleet/dha/policies returns seeded baseline policies', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/dha/policies');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.policies));
    assert.ok(data.policies.length >= 1);
    const baseline = data.policies.find(p => p.id === 'dha-policy-corporate-baseline');
    assert.ok(baseline, 'Should find seeded baseline policy');
    assert.equal(baseline.require_secure_boot, true);
    assert.equal(baseline.require_bitlocker, true);
  });

  test('DHA-03: POST /api/v1/fleet/dha/policies creates a new DHA hardware baseline policy', async () => {
    const newPolicy = {
      name: 'High-Security Executive Laptop Baseline',
      description: 'Strict PCR 0, 2, 4, 11 verification with mandatory HVCI and ELAM driver',
      require_secure_boot: true,
      require_bitlocker: true,
      require_virtualization_based_security: true,
      require_hypervisor_enforced_code_integrity: true,
      require_elam_driver: true,
      allowed_pcr_hashes: {
        pcr0: '8f4c2e1b9a7d3c5e',
        pcr2: '1a2b3c4d5e6f7a8b',
        pcr4: '9e8d7c6b5a4f3e2d',
        pcr11: '4b3c2d1e0f9a8b7c'
      },
      target_scope: 'ALL_FLEET'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/dha/policies', newPolicy);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.policy.name, newPolicy.name);
    assert.equal(data.policy.allowed_pcr_hashes.pcr0, '8f4c2e1b9a7d3c5e');
    createdPolicyId = data.policy.id;
  });

  test('DHA-04: POST /api/v1/fleet/dha/policies rejects request with missing name with 400', async () => {
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/dha/policies', { description: 'Missing name' });
    assert.equal(status, 400);
    assert.equal(data.error, 'NAME_REQUIRED');
  });

  test('DHA-05: GET /api/v1/fleet/dha/policies/:id returns specific policy by ID', async () => {
    const { status, data } = await apiRequest('GET', `/api/v1/fleet/dha/policies/${createdPolicyId}`);
    assert.equal(status, 200);
    assert.equal(data.id, createdPolicyId);
    assert.equal(data.require_secure_boot, true);
  });

  test('DHA-06: GET /api/v1/fleet/dha/policies/:id returns 404 for unknown ID', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/dha/policies/non-existent-pol');
    assert.equal(status, 404);
    assert.equal(data.error, 'POLICY_NOT_FOUND');
  });

  test('DHA-07: PATCH /api/v1/fleet/dha/policies/:id updates policy requirements and PCR hashes', async () => {
    const updatePayload = {
      description: 'Updated description with relaxed ELAM requirement',
      require_elam_driver: false
    };
    const { status, data } = await apiRequest('PATCH', `/api/v1/fleet/dha/policies/${createdPolicyId}`, updatePayload);
    assert.equal(status, 200);
    assert.equal(data.policy.description, updatePayload.description);
    assert.equal(data.policy.require_elam_driver, false);
  });

  test('DHA-08: DELETE /api/v1/fleet/dha/policies/:id removes policy and returns 200', async () => {
    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/dha/policies/${createdPolicyId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
    const check = await apiRequest('GET', `/api/v1/fleet/dha/policies/${createdPolicyId}`);
    assert.equal(check.status, 404);
  });

  test('DHA-09: GET /api/v1/fleet/dha/reports lists all DHA reports with device linkages', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/dha/reports');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.reports));
  });

  test('DHA-10: GET /api/v1/fleet/dha/reports?status=COMPLIANT filters reports by attestation status', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/dha/reports?status=COMPLIANT');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.reports));
    for (const r of data.reports) {
      assert.equal(r.attestation_status, 'COMPLIANT');
    }
  });

  test('DHA-11: GET /api/v1/fleet/devices/:id/dha/report retrieves latest attestation report for device', async () => {
    DeviceHealthAttestationEngine.verifyAttestationQuote(db, TEST_DEVICE_ID, {
      secure_boot_enabled: true,
      bitlocker_status: 'PROTECTION_ON',
      vbs_status: 'RUNNING',
      hvci_status: 'STRICT_ENFORCEMENT',
      tpm_pcr_measurements: { pcr0: 'a1b2c3d4e5f6', pcr2: 'b2c3d4e5f6a1', pcr4: 'c3d4e5f6a1b2', pcr11: 'd4e5f6a1b2c3' }
    });

    const { status, data } = await apiRequest('GET', `/api/v1/fleet/devices/${TEST_DEVICE_ID}/dha/report`);
    assert.equal(status, 200);
    assert.equal(data.device_id, TEST_DEVICE_ID);
    assert.equal(data.attestation_status, 'COMPLIANT');
    assert.equal(data.secure_boot_enabled, true);
  });

  test('DHA-12: GET /api/v1/fleet/devices/:id/dha/report returns 404 when device has no report', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/devices/non-existent-device/dha/report');
    assert.equal(status, 404);
    assert.equal(data.error, 'REPORT_NOT_FOUND');
  });

  test('DHA-13: POST /api/v1/nodes/:id/dha/attest verifies compliant TPM 2.0 quote and registers report', async () => {
    const quotePayload = {
      secure_boot_enabled: true,
      bitlocker_status: 'PROTECTION_ON',
      vbs_status: 'RUNNING',
      hvci_status: 'STRICT_ENFORCEMENT',
      tpm_pcr_measurements: {
        pcr0: 'a1b2c3d4e5f6',
        pcr2: 'b2c3d4e5f6a1',
        pcr4: 'c3d4e5f6a1b2',
        pcr11: 'd4e5f6a1b2c3'
      },
      tcg_event_log_summary: 'TCG Log: All UEFI stages and kernel boot measurements match golden signature.'
    };
    const { status, data } = await apiRequest('POST', `/api/v1/nodes/${TEST_DEVICE_ID}/dha/attest`, quotePayload);
    assert.equal(status, 200);
    assert.ok(data.success);
    assert.equal(data.report.attestation_status, 'COMPLIANT');
    assert.equal(data.report.bootkit_detected, false);
  });

  test('DHA-14: POST /api/v1/nodes/:id/dha/attest flags FAILED when Secure Boot is disabled', async () => {
    const nonCompliantPayload = {
      secure_boot_enabled: false,
      bitlocker_status: 'PROTECTION_ON',
      vbs_status: 'RUNNING',
      hvci_status: 'STRICT_ENFORCEMENT',
      tpm_pcr_measurements: { pcr0: 'a1b2c3d4e5f6' }
    };
    const { status, data } = await apiRequest('POST', `/api/v1/nodes/${TEST_DEVICE_ID}/dha/attest`, nonCompliantPayload);
    assert.equal(status, 200);
    assert.equal(data.report.attestation_status, 'FAILED');
    assert.equal(data.report.bootkit_detected, false);
  });

  test('DHA-15: POST /api/v1/nodes/:id/dha/attest detects PCR hash mismatch, sets TAMPERED status and bootkit_detected=true', async () => {
    const tamperedPayload = {
      secure_boot_enabled: true,
      bitlocker_status: 'PROTECTION_ON',
      vbs_status: 'RUNNING',
      hvci_status: 'STRICT_ENFORCEMENT',
      tpm_pcr_measurements: {
        pcr0: 'MALICIOUS_UNAUTHORIZED_FIRMWARE_HASH',
        pcr2: 'b2c3d4e5f6a1',
        pcr4: 'c3d4e5f6a1b2',
        pcr11: 'd4e5f6a1b2c3'
      }
    };
    const { status, data } = await apiRequest('POST', `/api/v1/nodes/${TEST_DEVICE_ID}/dha/attest`, tamperedPayload);
    assert.equal(status, 200);
    assert.equal(data.report.attestation_status, 'TAMPERED');
    assert.equal(data.report.bootkit_detected, true);
  });

  test('DHA-16: POST /api/v1/nodes/:id/dha/attest records critical security event when bootkit or PCR tampering is detected', async () => {
    const evt = db.prepare(`
      SELECT * FROM security_events 
      WHERE device_id = ? AND severity = 'CRITICAL'
      ORDER BY id DESC LIMIT 1
    `).get(TEST_DEVICE_ID);
    assert.ok(evt, 'Critical security event should be logged');
    assert.ok(evt.summary.includes('Bootkit or TPM PCR Hash Tampering'));
  });

  test('DHA-17: GET /api/v1/fleet/dha/microsegmentation lists zero-trust network policies', async () => {
    const { status, data } = await apiRequest('GET', '/api/v1/fleet/dha/microsegmentation');
    assert.equal(status, 200);
    assert.ok(Array.isArray(data.policies));
    assert.ok(data.policies.length >= 1);
  });

  test('DHA-18: POST /api/v1/fleet/dha/microsegmentation creates new zero-trust perimeter rule', async () => {
    const newRule = {
      name: 'Zero-Trust PCI Database Access Control',
      description: 'Block all untrusted access to production credit card databases',
      destination_cidr: '192.168.100.0/24',
      allowed_ports: ['3306', '5432'],
      protocol: 'TCP',
      action: 'REQUIRE_DHA_COMPLIANCE',
      enforcement_mode: 'ENFORCING'
    };
    const { status, data } = await apiRequest('POST', '/api/v1/fleet/dha/microsegmentation', newRule);
    assert.equal(status, 201);
    assert.ok(data.success);
    assert.equal(data.policy.name, newRule.name);
    assert.equal(data.policy.action, 'REQUIRE_DHA_COMPLIANCE');
    createdMspId = data.policy.id;
  });

  test('DHA-19: DELETE /api/v1/fleet/dha/microsegmentation/:id deletes microsegmentation rule', async () => {
    const { status, data } = await apiRequest('DELETE', `/api/v1/fleet/dha/microsegmentation/${createdMspId}`);
    assert.equal(status, 200);
    assert.ok(data.success);
    const check = await apiRequest('GET', '/api/v1/fleet/dha/microsegmentation');
    assert.ok(!check.data.policies.some(p => p.id === createdMspId));
  });

  test('DHA-20: GET /api/v1/fleet/devices/:id/dha/firewall-rules synthesizes WFP PowerShell rules enforcing DHA compliance', async () => {
    const { status, data } = await apiRequest('GET', `/api/v1/fleet/devices/${TEST_DEVICE_ID}/dha/firewall-rules`);
    assert.equal(status, 200);
    assert.equal(data.device_id, TEST_DEVICE_ID);
    assert.equal(typeof data.is_dha_compliant, 'boolean');
    assert.ok(Array.isArray(data.rules));
    assert.ok(data.powershell_script.includes('New-NetFirewallRule'));
  });
});
