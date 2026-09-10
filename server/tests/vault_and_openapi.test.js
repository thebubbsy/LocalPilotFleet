import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { initDb, closeDb } from '../src/db.js';
import { registerFleetRoutes } from '../src/routes/fleet.js';
import { registerNodeRoutes } from '../src/routes/nodes.js';
import { setFleetKey } from '../src/utils/auth.js';
import { SchemaValidator } from '../src/utils/schemaValidator.js';
import { VaultSecretsEngine } from '../src/services/vaultSecretsEngine.js';
import { openApiSpecEngine } from '../src/services/openApiSpecEngine.js';

describe('Enterprise Secrets Vault & OpenAPI Specification QA (vault_and_openapi.test.js)', () => {
  let server;
  let baseUrl;
  let db;
  const TEST_FLEET_KEY = 'test-vault-key-12345';

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

    server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const routeMatch = matchRoute(req.method, url.pathname);
      if (!routeMatch) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'NOT_FOUND' }));
        return;
      }
      req.params = routeMatch.params;
      req.query = Object.fromEntries(url.searchParams.entries());

      let bodyStr = '';
      req.on('data', chunk => { bodyStr += chunk; });
      req.on('end', () => {
        try {
          req.body = bodyStr ? JSON.parse(bodyStr) : {};
        } catch {
          req.body = {};
        }
        routeMatch.handler(req, res);
      });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    if (server) await new Promise(resolve => server.close(resolve));
    closeDb();
  });

  // Helper request
  async function apiRequest(path, options = {}) {
    const headers = {
      'x-fleet-key': TEST_FLEET_KEY,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };
    const res = await fetch(`${baseUrl}${path}`, {
      method: options.method || 'GET',
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { status: res.status, data };
  }

  // Tests
  test('VAULT-01: GET /api/v1/fleet/vault/stats returns baseline vault statistics', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/stats');
    assert.equal(res.status, 200);
    assert.ok(res.data.totalSecrets >= 2);
    assert.equal(res.data.zeroPlaintextStorage, true);
    assert.ok(res.data.hardwareProtection.includes('DPAPI-NG'));
  });

  test('VAULT-02: GET /api/v1/fleet/vault/secrets lists encrypted secrets without plaintext leakage', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/secrets');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.secrets));
    for (const sec of res.data.secrets) {
      assert.equal(sec.plaintext, undefined, 'Plaintext must NEVER be present in list response');
      assert.ok(sec.secret_id);
      assert.ok(sec.secret_scope);
    }
  });

  test('VAULT-03: POST /api/v1/fleet/vault/secrets stores raw secret under AES-256-GCM envelope', async () => {
    const payload = {
      secret_name: 'Test Production WiFi PSK',
      secret_scope: 'WIFI_PRESHARED_KEY',
      device_id: 'WORKSTATION-01',
      plaintext: 'SuperSecretWPA3EnterpriseKey2026!',
      rotation_interval_days: 60
    };
    const res = await apiRequest('/api/v1/fleet/vault/secrets', {
      method: 'POST',
      body: payload
    });
    assert.equal(res.status, 201);
    assert.ok(res.data.secret_id);
    assert.equal(res.data.secret_scope, 'WIFI_PRESHARED_KEY');
    assert.equal(res.data.encryption_scheme, 'AES_256_GCM_ENVELOPE_HSM');
  });

  test('VAULT-04: GET /api/v1/fleet/vault/secrets/:id retrieves single secret metadata', async () => {
    const listRes = await apiRequest('/api/v1/fleet/vault/secrets');
    const first = listRes.data.secrets[0];

    const res = await apiRequest(`/api/v1/fleet/vault/secrets/${first.secret_id}`);
    assert.equal(res.status, 200);
    assert.equal(res.data.secret_id, first.secret_id);
    assert.equal(res.data.secret_name, first.secret_name);
  });

  test('VAULT-05: POST /api/v1/fleet/vault/secrets/:id/decrypt rejects BitLocker decrypt without 4-eyes approval', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/secrets/sec-bitlocker-r0h12dj/decrypt', {
      method: 'POST',
      headers: { 'x-actor': 'JuniorHelpdeskOperator' },
      body: {}
    });
    assert.equal(res.status, 403);
    assert.ok(res.data.message.includes('DUAL_CUSTODY_REQUIRED'));
  });

  test('VAULT-06: POST /api/v1/fleet/vault/secrets/:id/decrypt succeeds for BitLocker with dual-custody reference', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/secrets/sec-bitlocker-r0h12dj/decrypt', {
      method: 'POST',
      headers: { 'x-actor': 'LeadSecurityEngineer' },
      body: { dual_custody_ref_id: 'apr-emergency-4eyes-9988' }
    });
    assert.equal(res.status, 200);
    assert.ok(res.data.plaintext || res.data.encrypted_payload_b64);
  });

  test('VAULT-07: POST /api/v1/fleet/vault/secrets/:id/decrypt allows emergency bypass for master-admin', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/secrets/sec-bitlocker-r0h12dj/decrypt', {
      method: 'POST',
      headers: { 'x-actor': 'master-admin' },
      body: {}
    });
    assert.equal(res.status, 200);
  });

  test('VAULT-08: GET /api/v1/fleet/vault/audits immutably tracks access and authorization events', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/audits?limit=10');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.data.audits));
    assert.ok(res.data.audits.length >= 2);
    const actions = res.data.audits.map(a => a.action);
    assert.ok(actions.includes('DECRYPT_AUTHORIZED') || actions.includes('STORE') || actions.includes('ACCESS_DENIED'));
  });

  test('VAULT-09: POST /api/v1/fleet/vault/secrets/:id/rotate re-encrypts secret with new plaintext', async () => {
    // Create secret first
    const createRes = await apiRequest('/api/v1/fleet/vault/secrets', {
      method: 'POST',
      body: {
        secret_name: 'Rotatable API Key',
        secret_scope: 'API_BEARER_TOKEN',
        plaintext: 'v1-old-token-abc'
      }
    });

    const secretId = createRes.data.secret_id;
    const rotateRes = await apiRequest(`/api/v1/fleet/vault/secrets/${secretId}/rotate`, {
      method: 'POST',
      body: { new_plaintext: 'v2-new-token-xyz' }
    });
    assert.equal(rotateRes.status, 200);
    assert.equal(rotateRes.data.secret_id, secretId);
  });

  test('VAULT-10: DELETE /api/v1/fleet/vault/secrets/:id deletes secret and records revocation audit', async () => {
    const createRes = await apiRequest('/api/v1/fleet/vault/secrets', {
      method: 'POST',
      body: {
        secret_name: 'Temporary Secret',
        secret_scope: 'API_BEARER_TOKEN',
        plaintext: 'temp-123'
      }
    });
    const secretId = createRes.data.secret_id;

    const delRes = await apiRequest(`/api/v1/fleet/vault/secrets/${secretId}`, {
      method: 'DELETE'
    });
    assert.equal(delRes.status, 200);
    assert.equal(delRes.data.success, true);

    const getRes = await apiRequest(`/api/v1/fleet/vault/secrets/${secretId}`);
    assert.equal(getRes.status, 404);
  });

  test('VAULT-11: POST /api/v1/nodes/:id/vault/escrow ingests workstation DPAPI-NG escrow payload', async () => {
    const res = await apiRequest('/api/v1/nodes/DESKTOP-TEST-NODE/vault/escrow', {
      method: 'POST',
      body: {
        secret_name: 'Node Local LAPS Password',
        secret_scope: 'LAPS_PASSWORD',
        encrypted_payload_b64: 'kL9xP8zQ1w4n7v3m==',
        encryption_scheme: 'DPAPI_NG_LOCAL_MACHINE',
        key_descriptor: 'SID:S-1-5-21-9999-1001'
      }
    });
    assert.equal(res.status, 201);
    assert.ok(res.data.secret_id);
  });

  test('VAULT-12: GET /api/v1/fleet/vault/powershell-snippet generates DPAPI-NG escrow script', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/powershell-snippet?scope=BITLOCKER_RECOVERY_KEY');
    assert.equal(res.status, 200);
    assert.ok(typeof res.data === 'string');
    assert.ok(res.data.includes('ProtectedData'));
    assert.ok(res.data.includes('DataProtectionScope]::LocalMachine'));
  });

  test('VAULT-13: Filtering secrets by secret_scope returns matching subset', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/secrets?secret_scope=BITLOCKER_RECOVERY_KEY');
    assert.equal(res.status, 200);
    for (const sec of res.data.secrets) {
      assert.equal(sec.secret_scope, 'BITLOCKER_RECOVERY_KEY');
    }
  });

  test('VAULT-14: Filtering secrets by device_id returns workstation scoped credentials', async () => {
    const res = await apiRequest('/api/v1/fleet/vault/secrets?device_id=DESKTOP-R0H12DJ');
    assert.equal(res.status, 200);
    for (const sec of res.data.secrets) {
      assert.equal(sec.device_id, 'DESKTOP-R0H12DJ');
    }
  });

  test('VAULT-15: Security rejection — missing fleet key returns 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/api/v1/fleet/vault/stats`);
    assert.equal(res.status, 401);
  });

  test('OPENAPI-01: GET /api/v1/openapi.json returns valid OpenAPI 3.0.3 specification', async () => {
    const res = await apiRequest('/api/v1/openapi.json');
    assert.equal(res.status, 200);
    assert.equal(res.data.openapi, '3.0.3');
    assert.ok(res.data.info.title.includes('LocalPilot Fleet'));
    assert.ok(res.data.paths['/api/v1/health']);
    assert.ok(res.data.paths['/api/v1/fleet/vault/stats']);
  });

  test('OPENAPI-02: OpenAPI specification defines enterprise security schemes', async () => {
    const res = await apiRequest('/api/v1/openapi.json');
    assert.equal(res.status, 200);
    const schemes = res.data.components.securitySchemes;
    assert.ok(schemes.FleetKeyAuth);
    assert.ok(schemes.NodeBearerAuth);
    assert.ok(schemes.MtlsCertAuth);
  });

  test('OPENAPI-03: OpenAPI specification defines enterprise functional tags', async () => {
    const res = await apiRequest('/api/v1/openapi.json');
    assert.equal(res.status, 200);
    const tagNames = res.data.tags.map(t => t.name);
    assert.ok(tagNames.includes('Agent Supervisor'));
    assert.ok(tagNames.includes('Enterprise Secrets Vault'));
    assert.ok(tagNames.includes('MSP Multi-Tenancy'));
    assert.ok(tagNames.includes('Cryptographic Identity & PKI'));
  });

  test('OPENAPI-04: GET /api/v1/docs serves interactive Swagger UI HTML explorer', async () => {
    const res = await apiRequest('/api/v1/docs');
    assert.equal(res.status, 200);
    assert.ok(typeof res.data === 'string');
    assert.ok(res.data.includes('swagger-ui'));
    assert.ok(res.data.includes('/api/v1/openapi.json'));
  });

  test('SCHEMA-01: SchemaValidator correctly enforces contract rules and catches violations', () => {
    const schema = {
      required: ['secret_name', 'secret_scope'],
      properties: {
        secret_name: { type: 'string', minLength: 3 },
        secret_scope: { type: 'string', enum: ['BITLOCKER_RECOVERY_KEY', 'LAPS_PASSWORD'] },
        rotation_interval_days: { type: 'integer' }
      }
    };

    const validPayload = {
      secret_name: 'BitLocker Key 01',
      secret_scope: 'BITLOCKER_RECOVERY_KEY',
      rotation_interval_days: 90
    };
    const validRes = SchemaValidator.validate(schema, validPayload);
    assert.equal(validRes.valid, true);

    const invalidPayload = {
      secret_name: 'X',
      secret_scope: 'INVALID_SCOPE',
      rotation_interval_days: 'not-an-integer'
    };
    const invalidRes = SchemaValidator.validate(schema, invalidPayload);
    assert.equal(invalidRes.valid, false);
    assert.ok(invalidRes.errors.length >= 3);
  });
});
