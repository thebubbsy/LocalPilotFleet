/**
 * LocalPilot Fleet — OpenAPI 3.0.3 Specification & Interactive API Explorer
 * Generates enterprise API contracts and documentation for all fleet endpoints.
 */

export class OpenApiSpecEngine {
  constructor() {
    this.spec = null;
  }

  getOpenApiSpec() {
    if (this.spec) return this.spec;

    this.spec = {
      openapi: '3.0.3',
      info: {
        title: 'LocalPilot Fleet Command Center API',
        version: '1.0.0-enterprise',
        description: 'Hardened on-premises endpoint management and security control plane with tier-1 enterprise feature parity.',
        contact: {
          name: 'LocalPilot Fleet Engineering',
          url: 'https://github.com/thebubbsy/LocalPilotFleet'
        },
        license: {
          name: 'MIT',
          url: 'https://opensource.org/licenses/MIT'
        }
      },
      servers: [
        {
          url: 'http://localhost:8443',
          description: 'LocalPilot Fleet Core Command Server'
        }
      ],
      tags: [
        { name: 'Core & Telemetry', description: 'Workstation inventory, health, and heartbeat streams' },
        { name: 'Agent Supervisor', description: 'Win32 Job Object containment, crash recovery, and watchdog supervision' },
        { name: 'Transport & Push', description: 'Persistent duplex WebSocket push channels and sub-3s dispatches' },
        { name: 'Cryptographic Identity & PKI', description: 'TPM 2.0 mTLS certificates, SCEP enrollment, and RSA-4096 signed payloads' },
        { name: 'Enterprise Secrets Vault', description: 'DPAPI-NG and AES-256-GCM envelope credential escrow (BitLocker & LAPS)' },
        { name: 'Content Distribution', description: 'Asynchronous BITS transfers and P2P subnet mesh cache' },
        { name: 'Native Windows MDM', description: 'OMA-DM CSP configuration, Autopilot 4K hashes, and WinRE crypto-wipe' },
        { name: 'Enterprise Governance', description: 'Granular RBAC, Dual-Custody 4-Eyes approvals, and RFC 5424 SIEM forwarders' },
        { name: 'MSP Multi-Tenancy', description: 'Logical organization scoping, campus sites, collections, and database HA' }
      ],
      components: {
        securitySchemes: {
          FleetKeyAuth: {
            type: 'apiKey',
            in: 'header',
            name: 'x-fleet-key',
            description: 'Master Fleet Administrator API Key'
          },
          NodeBearerAuth: {
            type: 'http',
            scheme: 'bearer',
            description: 'Workstation node authentication token'
          },
          MtlsCertAuth: {
            type: 'apiKey',
            in: 'header',
            name: 'x-client-cert-thumbprint',
            description: 'Hardware TPM 2.0 Client mTLS Certificate Thumbprint'
          }
        },
        schemas: {
          StandardError: {
            type: 'object',
            properties: {
              error: { type: 'string' },
              message: { type: 'string' }
            },
            required: ['error', 'message']
          },
          SupervisorStatus: {
            type: 'object',
            properties: {
              supervisor_pid: { type: 'integer' },
              worker_pid: { type: 'integer' },
              cpu_limit_percent: { type: 'integer', default: 5 },
              ram_limit_mb: { type: 'integer', default: 150 },
              job_object_active: { type: 'boolean' },
              anti_tamper_enabled: { type: 'boolean' }
            }
          },
          VaultSecretItem: {
            type: 'object',
            properties: {
              secret_id: { type: 'string' },
              secret_name: { type: 'string' },
              secret_scope: { type: 'string', enum: ['BITLOCKER_RECOVERY_KEY', 'LAPS_PASSWORD', 'MTLS_PRIVATE_KEY', 'API_BEARER_TOKEN', 'WIFI_PRESHARED_KEY'] },
              encryption_scheme: { type: 'string', enum: ['AES_256_GCM_ENVELOPE_HSM', 'DPAPI_NG_LOCAL_MACHINE', 'RSA_4096_PKI'] },
              device_id: { type: 'string' },
              rotation_interval_days: { type: 'integer' },
              is_active: { type: 'boolean' }
            }
          }
        }
      },
      security: [
        { FleetKeyAuth: [] }
      ],
      paths: {
        '/api/v1/health': {
          get: {
            summary: 'Health check endpoint',
            description: 'Returns operational status of the core server and SQLite database connection.',
            responses: {
              '200': {
                description: 'Server healthy',
                content: {
                  'application/json': {
                    schema: {
                      type: 'object',
                      properties: {
                        status: { type: 'string', example: 'ok' },
                        timestamp: { type: 'string', format: 'date-time' }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        '/api/v1/fleet/stats': {
          get: {
            tags: ['Core & Telemetry'],
            summary: 'Fleet-wide executive KPIs',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'Aggregated KPI metrics' }
            }
          }
        },
        '/api/v1/fleet/supervisor/stats': {
          get: {
            tags: ['Agent Supervisor'],
            summary: 'Host execution model and Job Object telemetry',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'Supervisor statistics' }
            }
          }
        },
        '/api/v1/fleet/push/stats': {
          get: {
            tags: ['Transport & Push'],
            summary: 'Real-time WebSocket push channel statistics',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'Push channel statistics' }
            }
          }
        },
        '/api/v1/fleet/vault/stats': {
          get: {
            tags: ['Enterprise Secrets Vault'],
            summary: 'DPAPI-NG & Hardware Secrets Vault metrics',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'Vault metrics' }
            }
          }
        },
        '/api/v1/fleet/vault/secrets': {
          get: {
            tags: ['Enterprise Secrets Vault'],
            summary: 'List encrypted vault secrets',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'List of encrypted secrets' }
            }
          },
          post: {
            tags: ['Enterprise Secrets Vault'],
            summary: 'Store a newly encrypted secret or encrypt plaintext under AES-256-GCM envelope',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '201': { description: 'Secret stored' }
            }
          }
        },
        '/api/v1/fleet/vault/secrets/{id}/decrypt': {
          post: {
            tags: ['Enterprise Secrets Vault'],
            summary: 'Decrypt vault secret (enforces Dual-Custody 4-Eyes for BitLocker & LAPS)',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'Decrypted secret' },
              '403': { description: 'Dual-custody authorization required' }
            }
          }
        },
        '/api/v1/fleet/tenancy/stats': {
          get: {
            tags: ['MSP Multi-Tenancy'],
            summary: 'Multi-tenancy organization and site metrics',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'Tenancy statistics' }
            }
          }
        },
        '/api/v1/fleet/tenancy/database-health': {
          get: {
            tags: ['MSP Multi-Tenancy'],
            summary: 'Database HA abstraction & PostgreSQL readiness diagnostics',
            security: [{ FleetKeyAuth: [] }],
            responses: {
              '200': { description: 'Database health' }
            }
          }
        }
      }
    };

    return this.spec;
  }

  generateSwaggerHtml() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>LocalPilot Fleet — OpenAPI Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .top-banner { background: #1e293b; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
    .top-banner h1 { margin: 0; font-size: 1.25rem; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
    .badge { background: #0284c7; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    #swagger-ui { background: white; border-radius: 8px; margin: 20px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
  </style>
</head>
<body>
  <div class="top-banner">
    <h1>🛡️ LocalPilot Fleet Command Center — Interactive OpenAPI 3.0 Explorer</h1>
    <span class="badge">Tier-1 Enterprise Specification</span>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/api/v1/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>`;
  }
}

export const openApiSpecEngine = new OpenApiSpecEngine();
