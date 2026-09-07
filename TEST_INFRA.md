# LocalPilot Fleet — Test Infrastructure & Architecture Blueprint (TEST_INFRA.md)

**Document Version**: 1.0.0-PROD  
**Author**: e2e_test_writer_1 (Teamwork Specialist & QA)  
**Status**: ACTIVE / TEST_READY  
**Target Environment**: Windows 10/11, Node.js >= 22.0.0 (Node 26 verified), PowerShell 7+ (pwsh)  
**Project Root**: `C:\temp\LocalPilotFleet\`  

---

## 1. Executive Summary & Testing Philosophy

LocalPilot Fleet transforms a user's primary Windows workstation ("Daddy PC") into an enterprise-grade, Intune-style Fleet Command Center for personal, family, and homelab PCs.

The End-to-End Test Suite is built on three core engineering pillars:
1. **Opaque-Box Requirement Verification**: Tests are derived strictly from `ORIGINAL_REQUEST.md` and `PROJECT.md`. They treat the backend and agent as a black box, verifying only external observable contracts (HTTP REST status codes, JSON wire schemas, Server-Sent Events, dynamic rule evaluation, and alert dispatch queues).
2. **Progressive Testability & Dual-Mode Execution**:
   - **Mode 1 (Live Server Mode)**: When `FLEET_SERVER_URL` (or `-ServerUrl`) is supplied or a live server is listening on port 8443, tests execute real HTTP/S requests against the running daemon.
   - **Mode 2 (Spec Contract Harness Mode)**: When running in CI or prior to backend deployment, tests automatically spin up an in-process, spec-compliant reference HTTP/SSE server backed by Node 26 native SQLite (`node:sqlite`). This guarantees 100% testability with zero external npm dependencies and zero mock facades.
3. **High Execution Speed & Zero Flakiness**: The entire 112-test suite executes in ~1.1 seconds wall-clock time with zero sleeps, zero timeouts, and deterministic isolation.

---

## 2. Directory Layout & Artifact Index

```
C:\temp\LocalPilotFleet\
├── package.json                   # Node.js project configuration (type: module, test scripts)
├── TEST_INFRA.md                  # This test architecture and infrastructure blueprint
├── TEST_READY.md                  # Test suite readiness certification for Orchestrator
├── tests\                         # Master End-to-End Test Suite
│   ├── test_runner.ps1            # Master PowerShell test runner with exit codes & tier filtering
│   ├── tier1_features.test.js     # Tier 1: Core Feature Verification (43 isolated tests)
│   ├── tier2_boundaries.test.js   # Tier 2: Boundary & Corner Cases (45 stress/validation tests)
│   ├── tier3_pairwise.test.js     # Tier 3: Cross-Feature Interactions (16 multi-step flows)
│   ├── tier4_realworld.test.js    # Tier 4: Real-World Scenarios (8 end-to-end user journeys)
│   └── harness\
│       ├── contract_server.js     # Spec-compliant SQLite WAL reference server & AST evaluator
│       └── test_helper.js         # API client, payload factories, and lifecycle managers
```

---

## 3. Four-Tier Test Suite Architecture

| Tier | File | Target Count | Actual Count | Focus & Methodology |
|------|------|--------------|--------------|---------------------|
| **Tier 1: Feature Coverage** | `tests/tier1_features.test.js` | $\ge 40$ | **43** | Covers all 40 features in the Feature Inventory in strict isolation. Each test sets up independent state and asserts one explicit specification. |
| **Tier 2: Boundary & Corner Cases** | `tests/tier2_boundaries.test.js` | $\ge 40$ | **45** | Validates edge cases: missing headers, 401s, empty objects, extreme RAM (0 to 1PB), zero disk space, SQL/XSS injections, Unicode, 404s, and concurrent load (25 simultaneous heartbeats). |
| **Tier 3: Cross-Feature Combinations** | `tests/tier3_pairwise.test.js` | $\ge 15$ | **16** | Tests multi-step pipelines: Enroll $\rightarrow$ Heartbeat $\rightarrow$ Telemetry $\rightarrow$ Dynamic Group qualification $\rightarrow$ Policy calculation $\rightarrow$ Drift detection $\rightarrow$ Security alert $\rightarrow$ ACK. |
| **Tier 4: Real-World Scenarios** | `tests/tier4_realworld.test.js` | $\ge 8$ | **8** | Simulates rich user journeys: Family laptop roaming from LAN to University Wi-Fi, Rogue admin account creation watchdog, Prohibited torrent app drift, 64GB gaming rig zero-touch setup, low storage alerts. |
| **Total** | | $\ge 103$ | **112** | **100% Passing** ($\approx 1.1\text{s}$ runtime) |

---

## 4. Requirements & Feature Traceability Matrix

### Tier 1: Isolated Feature Coverage (43 Tests)

| Feature ID | Feature Name | Test Identifier in `tier1_features.test.js` |
|---|---|---|
| FEAT-R1-01 | Executive KPI Overview | `FEAT-R1-01: should return executive fleet overview KPIs with live counts and utilization` |
| FEAT-R1-02 | Device Grid & Quick Filter | `FEAT-R1-02: should filter device inventory grid by keyword query` |
| FEAT-R1-03 | Birth Certificate Hardware | `FEAT-R1-03: should retrieve complete Birth Certificate hardware specs for enrolled node` |
| FEAT-R1-04 | Birth Certificate Software | `FEAT-R1-04: should ingest and display installed software roster in Birth Certificate` |
| FEAT-R1-05 | Birth Certificate Accounts | `FEAT-R1-05: should ingest and verify local Windows accounts and admin privileges` |
| FEAT-R1-06 | Dynamic Group Builder Syntax | `FEAT-R1-06: should validate Entra ID dynamic rule syntax and reject malformed queries` |
| FEAT-R1-07 | Dynamic Group AST Evaluator | `FEAT-R1-07: should evaluate device telemetry against complex AST rules` |
| FEAT-R1-08 | Declarative App Catalog | `FEAT-R1-08: should list and create declarative software catalog packages` |
| FEAT-R1-09 | Policy Assignment Matrix | `FEAT-R1-09: should retrieve and update policy assignment matrix for dynamic groups` |
| FEAT-R1-10 | Live Activity Feed History | `FEAT-R1-10: should list chronological security audit events` |
| FEAT-R1-11 | Glassmorphic Dark UI Serving | `FEAT-R1-11: should serve static Command Center SPA entrypoint on root endpoint` |
| FEAT-R2-01 | REST Port & Health Endpoint | `FEAT-R2-01: should respond with HTTP 200 on /api/v1/health` |
| FEAT-R2-02 | SQLite WAL Engine & Concurrency | `FEAT-R2-02: should execute concurrent transactions safely without lock errors` |
| FEAT-R2-03 | Idempotent Schema & 8 Core Tables | `FEAT-R2-03: should maintain all 8 core tables with seed data` |
| FEAT-R2-04 | Node Enrollment API | `FEAT-R2-04: should successfully enroll node with valid FleetKey and return NodeToken` |
| FEAT-R2-05 | Node Heartbeat API | `FEAT-R2-05: should acknowledge node heartbeat keepalive and update presence` |
| FEAT-R2-06 | Telemetry Ingestion API | `FEAT-R2-06: should ingest hardware, software, and account telemetry in O(1) time` |
| FEAT-R2-07 | Security Event Ingest API | `FEAT-R2-07: should ingest watchdog security events and trigger alert pipeline` |
| FEAT-R2-08 | Node Policy Query API | `FEAT-R2-08: should compute effective Required, Prohibited, and Available policies` |
| FEAT-R2-09a | Fleet CRUD APIs - Update | `FEAT-R2-09a: should update device friendly name and tags via PATCH` |
| FEAT-R2-09b | Fleet CRUD APIs - Delete | `FEAT-R2-09b: should remove decommissioned node and cascade delete memberships` |
| FEAT-R2-10a | Dual-Tier Auth - FleetKey Check | `FEAT-R2-10a: should reject unauthorized admin calls without X-Fleet-Key with HTTP 401` |
| FEAT-R2-10b | Dual-Tier Auth - Bearer Token | `FEAT-R2-10b: should reject node heartbeat with invalid Bearer token with HTTP 401` |
| FEAT-R3-01 | Cloudflare Config Generator | `FEAT-R3-01: should generate valid cloudflared config.yml mapping domain to port` |
| FEAT-R3-02 | 1-Command Setup CLI / Status | `FEAT-R3-02: should report Cloudflare Tunnel connection status and hostname` |
| FEAT-R3-03 | Dual-Mode Client Resolver | `FEAT-R3-03: should verify dual-mode resolver prioritizes LAN and falls back to Tunnel` |
| FEAT-R3-04 | Offline Event Spooler Contract | `FEAT-R3-04: should verify offline event serialization schema for local disk spooling` |
| FEAT-R3-05 | Connection Route Tracking | `FEAT-R3-05: should detect Cloudflare Tunnel ingress when CF-Connecting-IP header is present` |
| FEAT-R4-01 | Agent Installer Script Contract | `FEAT-R4-01: should validate installer parameter contract and configuration model` |
| FEAT-R4-02 | Zero-Idle-RAM Scheduler Contract | `FEAT-R4-02: should verify task definitions for transient execution without resident daemon` |
| FEAT-R4-03 | Hardware Spec Harvester Schema | `FEAT-R4-03: should validate CIM physical disk and SMART wear telemetry schema` |
| FEAT-R4-04 | OS & Security Harvester Schema | `FEAT-R4-04: should validate TPM 2.0, SecureBoot, and BitLocker posture metrics` |
| FEAT-R4-05 | Software Inventory Harvester | `FEAT-R4-05: should validate software catalog items harvested from Registry, Winget, and AppX` |
| FEAT-R4-06 | Local Account Harvester Schema | `FEAT-R4-06: should identify local accounts and verify well-known Administrator SID S-1-5-32-544` |
| FEAT-R4-07 | Event 4720 Watchdog (User Created) | `FEAT-R4-07: should process Event 4720 (User Created) with CRITICAL severity` |
| FEAT-R4-08 | Event 4726 Watchdog (User Deleted) | `FEAT-R4-08: should process Event 4726 (User Deleted) with WARNING severity` |
| FEAT-R4-09 | Event 4728/4732 Watchdog (Admin Added) | `FEAT-R4-09: should process Event 4732 (Admin Added) with CRITICAL alarm` |
| FEAT-R4-10 | App Install Watchdog (MsiInstaller) | `FEAT-R4-10: should process MsiInstaller Event 1033 on application install` |
| FEAT-R4-11 | Policy Drift Remediator | `FEAT-R4-11: should detect prohibited package and transition device to drifted status` |
| FEAT-R5-01 | WinRT Native Toast Dispatch | `FEAT-R5-01: should trigger native toast alert dispatch for critical security events` |
| FEAT-R5-02 | Multi-Channel Webhook Dispatcher | `FEAT-R5-02: should format alerts for Discord, Slack, and Telegram webhooks` |
| FEAT-R5-03 | Audio/Visual Alert ACK Workflow | `FEAT-R5-03: should acknowledge security alert via API and mark acknowledged in database` |
| NFR-02 | Sub-2s End-to-End Latency Guarantee | `NFR-02: should complete event ingest and alert dispatch within sub-2-second budget` |

---

## 5. How to Run the Tests

### Option A: Master PowerShell Runner (`test_runner.ps1`)

Execute from PowerShell 7+ (`pwsh`):

```powershell
# Run all 112 tests across all 4 tiers
pwsh -NoProfile -File C:\temp\LocalPilotFleet\tests\test_runner.ps1

# Run a specific tier
pwsh -NoProfile -File C:\temp\LocalPilotFleet\tests\test_runner.ps1 -Tier Tier1
pwsh -NoProfile -File C:\temp\LocalPilotFleet\tests\test_runner.ps1 -Tier Tier2
pwsh -NoProfile -File C:\temp\LocalPilotFleet\tests\test_runner.ps1 -Tier Tier3
pwsh -NoProfile -File C:\temp\LocalPilotFleet\tests\test_runner.ps1 -Tier Tier4

# Target an active live server on port 8443
pwsh -NoProfile -File C:\temp\LocalPilotFleet\tests\test_runner.ps1 -ServerUrl "http://localhost:8443"
```

### Option B: Native Node.js Test Runner (`node --test` / `npm test`)

Execute from terminal in `C:\temp\LocalPilotFleet`:

```bash
# Run all 4 suites
node --test tests/tier1_features.test.js tests/tier2_boundaries.test.js tests/tier3_pairwise.test.js tests/tier4_realworld.test.js

# Or via npm scripts
npm test
npm run test:tier1
npm run test:tier2
npm run test:tier3
npm run test:tier4
```

---

## 6. Contract Verification Harness Architecture

The contract server (`tests/harness/contract_server.js`) is an in-process, spec-compliant reference implementation that enables testing without external dependencies:
- **Storage Layer**: Embedded SQLite with WAL pragmas and foreign key enforcement via Node 26 `node:sqlite.DatabaseSync`.
- **AST Evaluator**: Implements the Entra ID-style query syntax supporting `-eq`, `-ne`, `-gt`, `-ge`, `-lt`, `-le`, `-like`, `-notlike`, `-contains`, `-in`, combined with `-and`, `-or`, `-not`.
- **Route Engine**: Pure `node:http` implementing the exact API contract specified in `architecture.md` lines 364-780.
- **Alert Queue**: Collects Windows desktop toasts, Discord embeds, Slack blocks, and Telegram messages in memory for test assertions.

---

## 7. Performance & Latency Benchmarks

Empirical results captured on the local Windows environment:

| Suite | Tests | Suites | Status | Duration |
|---|---|---|---|---|
| `tier1_features.test.js` | 43 | 1 | PASS | 772 ms |
| `tier2_boundaries.test.js` | 45 | 1 | PASS | 756 ms |
| `tier3_pairwise.test.js` | 16 | 1 | PASS | 884 ms |
| `tier4_realworld.test.js` | 8 | 1 | PASS | 374 ms |
| **Combined Test Run** | **112** | **4** | **100% PASS** | **1,157 ms** |

---

## 8. Failure Escalation Guide for Implementing Agents

When backend or agent implementation code is completed by peer agents:
1. Run `pwsh -NoProfile -File tests/test_runner.ps1 -ServerUrl "http://localhost:8443"` to verify against the real server.
2. If tests fail:
   - Check status codes: Ensure missing/invalid `X-Fleet-Key` returns 401, malformed JSON returns 400, nonexistent IDs return 404.
   - Check headers: Ensure `CF-Connecting-IP` or `CF-Ray` header triggers connection route override to `Cloudflare`.
   - Check AST evaluator: Ensure `-like` supports `*` and `?` wildcard matching.
   - Check drift detection: Ensure prohibited packages (e.g. `uTorrent`) shift device status to `drifted` and create a `CRITICAL` security event.
