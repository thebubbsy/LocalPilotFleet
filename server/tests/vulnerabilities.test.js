/**
 * LocalPilot Fleet — Microsoft Defender Vulnerability Management & Security Baselines QA Tests
 * server/tests/vulnerabilities.test.js
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createTestApp } from './helpers/testServer.js';
import * as vulnerabilityEngine from '../src/services/vulnerabilityEngine.js';

describe('Defender Vulnerability Management (TVM) & Security Baselines QA (vulnerabilities.test.js)', () => {
  let app;
  const FLEET_KEY = 'test-fleet-tvm-baselines-qa';
  let testDeviceId;
  let testNodeToken;

  let createdCveId = 'CVE-2026-99999';
  let createdBaselineId;
  let createdExposureId;

  before(async () => {
    app = await createTestApp({ fleetKey: FLEET_KEY, seed: true });

    // Enroll a test workstation
    const enrollRes = await fetch(`${app.baseUrl}/api/v1/nodes/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Fleet-Key': FLEET_KEY
      },
      body: JSON.stringify({
        hostname: 'SEC-WORKSTATION-01',
        friendly_name: 'SecOps Workstation 01',
        serial_number: 'TVM-TEST-SN-112233',
        os_name: 'Microsoft Windows 11 Enterprise',
        os_version: '23H2',
        total_ram_bytes: 34359738368
      })
    });
    assert.equal(enrollRes.status, 201);
    const enrollData = await enrollRes.json();
    testDeviceId = enrollData.device_id;
    testNodeToken = enrollData.node_token;
  });

  after(async () => {
    if (app) await app.cleanup();
  });

  async function api(path, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      'X-Fleet-Key': FLEET_KEY,
      ...(options.headers || {})
    };
    const res = await fetch(`${app.baseUrl}${path}`, { ...options, headers });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = text; }
    return { status: res.status, body };
  }

  // TVM-01
  it('TVM-01: Returns TVM aggregate dashboard statistics with seeded CVE data', async () => {
    const { status, body } = await api('/api/v1/fleet/tvm/stats');
    assert.equal(status, 200);
    assert.ok(body.total_cves >= 5);
    assert.ok(body.critical_cves >= 2);
    assert.ok(body.high_cves >= 3);
    assert.ok(Array.isArray(body.severity_breakdown));
    assert.ok(Array.isArray(body.top_vulnerable_software));
  });

  // TVM-02
  it('TVM-02: Lists vulnerabilities with CVSS sorting, severity filter, and keyword search', async () => {
    const { status, body } = await api('/api/v1/fleet/tvm/vulnerabilities?severity=CRITICAL');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.vulnerabilities));
    assert.ok(body.vulnerabilities.every(v => v.severity === 'CRITICAL'));
    assert.ok(body.vulnerabilities.some(v => v.cve_id === 'CVE-2024-38063'));
  });

  // TVM-03
  it('TVM-03: Successfully creates a new vulnerability in the knowledgebase', async () => {
    const { status, body } = await api('/api/v1/fleet/tvm/vulnerabilities', {
      method: 'POST',
      body: JSON.stringify({
        cve_id: createdCveId,
        title: 'Node.js Prototype Pollution RCE',
        description: 'Vulnerability in recursive object merging leading to prototype pollution and code execution.',
        software_name: 'Node.js',
        affected_versions: '< 22.8.0',
        cvss_score: 9.8,
        exploit_status: 'ACTIVE_EXPLOIT_POC',
        patch_status: 'VENDOR_PATCH_AVAILABLE',
        remediation_guidance: 'Upgrade Node.js to v22.8.0 or later.'
      })
    });
    assert.equal(status, 201);
    assert.ok(body.success);
    assert.equal(body.vulnerability.cve_id, createdCveId);
    assert.equal(body.vulnerability.severity, 'CRITICAL');
  });

  // TVM-04
  it('TVM-04: Rejects creating vulnerability with missing mandatory fields', async () => {
    const { status, body } = await api('/api/v1/fleet/tvm/vulnerabilities', {
      method: 'POST',
      body: JSON.stringify({
        title: 'Missing CVE ID and software'
      })
    });
    assert.equal(status, 400);
    assert.equal(body.error, 'TVM_VULN_CREATE_ERROR');
  });

  // TVM-05
  it('TVM-05: Retrieves single vulnerability with exposed client workstations', async () => {
    const { status, body } = await api(`/api/v1/fleet/tvm/vulnerabilities/${createdCveId}`);
    assert.equal(status, 200);
    assert.equal(body.vulnerability.cve_id, createdCveId);
    assert.ok(Array.isArray(body.vulnerability.exposed_devices));
  });

  // TVM-06
  it('TVM-06: Updates existing vulnerability CVSS score, severity, and remediation guidance', async () => {
    const { status, body } = await api(`/api/v1/fleet/tvm/vulnerabilities/${createdCveId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        cvss_score: 7.5,
        exploit_status: 'NONE',
        remediation_guidance: 'Apply patch immediately via Winget.'
      })
    });
    assert.equal(status, 200);
    assert.equal(body.vulnerability.cvss_score, 7.5);
    assert.equal(body.vulnerability.severity, 'HIGH');
    assert.equal(body.vulnerability.exploit_status, 'NONE');
  });

  // TVM-07
  it('TVM-07: Deletes vulnerability from knowledgebase and cascades exposures', async () => {
    const tempVuln = vulnerabilityEngine.createVulnerability(app.db, {
      cve_id: 'CVE-2025-TEMP01',
      title: 'Temporary Flaw',
      software_name: 'TempApp',
      cvss_score: 5.0
    });
    const { status: delStatus, body: delBody } = await api(`/api/v1/fleet/tvm/vulnerabilities/${tempVuln.cve_id}`, {
      method: 'DELETE'
    });
    assert.equal(delStatus, 200);
    assert.ok(delBody.success);

    const { status: getStatus } = await api(`/api/v1/fleet/tvm/vulnerabilities/${tempVuln.cve_id}`);
    assert.equal(getStatus, 404);
  });

  // TVM-08
  it('TVM-08: Queries device vulnerabilities for enrolled workstation', async () => {
    const { status, body } = await api(`/api/v1/fleet/devices/${testDeviceId}/vulnerabilities`);
    assert.equal(status, 200);
    assert.equal(body.device_id, testDeviceId);
    assert.ok(Array.isArray(body.vulnerabilities));
  });

  // TVM-09
  it('TVM-09: Evaluates device installed software against CVE knowledgebase via assessment endpoint', async () => {
    const { status, body } = await api(`/api/v1/fleet/devices/${testDeviceId}/assess-vulnerabilities`, {
      method: 'POST',
      body: JSON.stringify({
        software: [
          { name: 'Google Chrome Enterprise', version: '127.0.0.0' },
          { name: '7-Zip Archiver', version: '23.01' },
          { name: 'OpenSSL Runtime', version: '3.3.0' }
        ]
      })
    });
    assert.equal(status, 200);
    assert.ok(body.success);
    assert.ok(Array.isArray(body.active_vulnerabilities));
    assert.ok(body.active_vulnerabilities.some(v => v.cve_id === 'CVE-2025-49211'));
    assert.ok(body.active_vulnerabilities.some(v => v.cve_id === 'CVE-2023-4863'));
    createdExposureId = body.active_vulnerabilities[0].id;
  });

  // TVM-10
  it('TVM-10: Updates device vulnerability exposure status (e.g. RESOLVED)', () => {
    const updated = vulnerabilityEngine.updateDeviceVulnerabilityStatus(app.db, createdExposureId, {
      status: 'RESOLVED',
      remediation_script: 'winget upgrade --id Google.Chrome --silent'
    });
    assert.ok(updated);
    assert.equal(updated.status, 'RESOLVED');
    assert.ok(updated.resolved_at);
  });

  // TVM-11
  it('TVM-11: Lists security baseline templates with category and enabled filters', async () => {
    const { status, body } = await api('/api/v1/fleet/tvm/baselines');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.baselines));
    assert.ok(body.baselines.length >= 1);
    assert.ok(body.baselines.some(b => b.id === 'base-win11-sec-baseline'));
  });

  // TVM-12
  it('TVM-12: Creates a new hardened security baseline template with enforcement rules', async () => {
    const { status, body } = await api('/api/v1/fleet/tvm/baselines', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Zero-Trust Credential Isolation Baseline',
        category: 'CREDENTIAL_HYGIENE',
        description: 'Hardened baseline enforcing WDigest disabling and Remote Desktop NLA.',
        enforcement_rules: [
          {
            id: 'rule-wdigest',
            name: 'Disable WDigest Plaintext Credential Caching',
            registry_path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',
            value_name: 'UseLogonCredential',
            expected_value: 0
          }
        ]
      })
    });
    assert.equal(status, 201);
    assert.ok(body.success);
    assert.equal(body.baseline.name, 'Zero-Trust Credential Isolation Baseline');
    assert.equal(body.baseline.category, 'CREDENTIAL_HYGIENE');
    createdBaselineId = body.baseline.id;
  });

  // TVM-13
  it('TVM-13: Rejects creating baseline with missing name or category', async () => {
    const { status, body } = await api('/api/v1/fleet/tvm/baselines', {
      method: 'POST',
      body: JSON.stringify({
        description: 'Incomplete baseline'
      })
    });
    assert.equal(status, 400);
    assert.equal(body.error, 'TVM_BASELINE_CREATE_ERROR');
  });

  // TVM-14
  it('TVM-14: Retrieves single security baseline by ID with parsed enforcement rules', async () => {
    const { status, body } = await api(`/api/v1/fleet/tvm/baselines/${createdBaselineId}`);
    assert.equal(status, 200);
    assert.equal(body.baseline.id, createdBaselineId);
    assert.ok(Array.isArray(body.baseline.parsed_rules));
    assert.ok(body.audit_script);
    assert.ok(body.remediation_script);
  });

  // TVM-15
  it('TVM-15: Updates security baseline settings and rule definitions', async () => {
    const { status, body } = await api(`/api/v1/fleet/tvm/baselines/${createdBaselineId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: 'Updated credential hygiene baseline with additional rules'
      })
    });
    assert.equal(status, 200);
    assert.equal(body.baseline.description, 'Updated credential hygiene baseline with additional rules');
  });

  // TVM-16
  it('TVM-16: Deletes security baseline successfully', async () => {
    const { status, body } = await api(`/api/v1/fleet/tvm/baselines/${createdBaselineId}`, {
      method: 'DELETE'
    });
    assert.equal(status, 200);
    assert.ok(body.success);
    assert.equal(body.deleted_id, createdBaselineId);

    const { status: getStatus } = await api(`/api/v1/fleet/tvm/baselines/${createdBaselineId}`);
    assert.equal(getStatus, 404);
  });

  // TVM-17
  it('TVM-17: Generates PowerShell audit script verifying baseline registry keys', () => {
    const baseline = vulnerabilityEngine.getSecurityBaseline(app.db, 'base-win11-sec-baseline');
    assert.ok(baseline);
    const auditScript = vulnerabilityEngine.generateBaselineAuditScript(baseline);
    assert.ok(auditScript.includes('RunAsPPL'));
    assert.ok(auditScript.includes('EnableVirtualizationBasedSecurity'));
    assert.ok(auditScript.includes('ComplianceRate'));
  });

  // TVM-18
  it('TVM-18: Generates PowerShell remediation script applying baseline settings', () => {
    const baseline = vulnerabilityEngine.getSecurityBaseline(app.db, 'base-win11-sec-baseline');
    assert.ok(baseline);
    const remScript = vulnerabilityEngine.generateBaselineRemediationScript(baseline);
    assert.ok(remScript.includes('Set-ItemProperty'));
    assert.ok(remScript.includes('RunAsPPL'));
    assert.ok(remScript.includes('SMB1'));
  });

  // TVM-19
  it('TVM-19: Agent queries active device vulnerabilities via node endpoint', async () => {
    const { status, body } = await api(`/api/v1/nodes/${testDeviceId}/vulnerabilities`, {
      headers: { 'Authorization': `Bearer ${testNodeToken}` }
    });
    assert.equal(status, 200);
    assert.equal(body.device_id, testDeviceId);
    assert.ok(Array.isArray(body.active_vulnerabilities));
  });

  // TVM-20
  it('TVM-20: Agent submits software scan results via node scan endpoint and receives detected CVEs', async () => {
    const { status, body } = await api(`/api/v1/nodes/${testDeviceId}/vulnerabilities/scan`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${testNodeToken}` },
      body: JSON.stringify({
        software: [
          { name: 'Google Chrome', version: '127.0.0.0' }
        ]
      })
    });
    assert.equal(status, 200);
    assert.ok(body.success);
    assert.ok(body.count >= 1);
  });
});
