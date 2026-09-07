# Original User Request

## Initial Request — 2026-09-07T15:08:59Z

Build LocalPilot Fleet, a high-effort, Silicon Valley investor-pitch-tier web-based Intune Admin Portal for personal, family, and homelab Windows device fleets. The system transforms the user's primary workstation ("Daddy PC") into a centralized Fleet Command Center backed by a local SQLite database, a secure REST API on a dedicated port, Cloudflare Tunnel reverse proxy integration for roaming/remote devices, and a client agent reporting full hardware/software telemetry, enforcing dynamic device groups, deploying/patching applications, and firing instant watchdog alerts on new user creation or unapproved app installations.

Working directory: C:\temp\LocalPilotFleet
Integrity mode: development

## Requirements

### R1. Fleet Command Center Web Dashboard (Silicon Valley Pitch Tier)
Deliver a modern, ultra-responsive single-page web console (matching the dark-mode, card-based aesthetic of OnYaChamp):
- Executive Fleet Overview: Real-time KPI cards (Total Fleet Devices, Online/Offline status, Compliant/Drifted count, Critical Security Alerts, Storage/RAM fleet utilization).
- Device Management & Deep Inspection: Interactive table of all managed nodes with quick search, tags, OS build, IP address, connection route (Local LAN vs Cloudflare Tunnel), and last check-in. Clicking a device opens a comprehensive "Birth Certificate" inspector showing CPU, RAM, NVMe health, GPU, TPM 2.0, SecureBoot, active network adapters, installed applications, and local user accounts.
- Dynamic Device Groups: Replicate Entra ID dynamic query membership (e.g., Device.TotalRAM_GB -ge 32, Device.Group -eq 'Family', Device.HasBattery -eq true, Device.OSVersion -like '10.0.226*', Device.GPU -like '*NVIDIA*').
- Application Assignment & Policy Matrix: Declarative app catalog assigning packages as Required (auto-enforced via Winget), Prohibited (auto-uninstalled and flagged), or Available.
- Live Fleet Activity & Security Audit Feed: Real-time event stream showing security events, drift remediations, and check-ins.

### R2. Backend Service & SQLite Database Engine
- Fast, lightweight REST API server running on a configurable port (default :8443 or :8080) backed by a persistent SQLite database (fleet.db).
- Schema with migrations for: devices, telemetry_snapshots, dynamic_groups, group_memberships, software_catalog, policy_assignments, security_events, fleet_settings.
- High-performance endpoints for:
  - Node enrollment (POST /api/v1/nodes/enroll) with mutual pre-shared FleetKey validation.
  - Telemetry check-in (POST /api/v1/nodes/heartbeat and POST /api/v1/nodes/telemetry).
  - Security event ingest (POST /api/v1/nodes/events).
  - Policy query (GET /api/v1/nodes/:id/policy).
  - Dashboard stats & CRUD (GET /api/v1/fleet/*).

### R3. Cloudflare Tunnel & Hybrid Connectivity Engine
- Built-in configuration generator and CLI integration for Cloudflare Tunnel (cloudflared).
- Generates 1-command zero-trust reverse proxy setup so roaming client PCs (e.g., family laptops on school/travel Wi-Fi, off-site VMs) securely report back to the Daddy Server without opening router firewall ports or exposing public IPs.
- Dual-mode client resolver: tries low-latency LAN first, falls back to secure Cloudflare Tunnel endpoint when off-grid.

### R4. Client Node Agent & Real-Time Event Watchdog
- Lightweight, zero-idle-RAM client reporting agent package (Install-LocalPilotNode.ps1 / Invoke-LocalPilotAgent.ps1):
  - Comprehensive telemetry harvest: Hardware (Motherboard serial, CPU ID, RAM modules, Disks), OS & Security status (TPM 2.0, Secure Boot, BitLocker), installed software list (Winget, Registry, AppX), and local Windows user accounts.
  - Windows Event Log Watchdog: Native event-triggered task monitoring:
    - Event 4720: New local user account created.
    - Event 4726: Local user account deleted.
    - Event 4728 / 4732: User added to local Administrators group.
    - MsiInstaller / AppX: New application installed.
  - Instant dispatch to Master Server webhook endpoint upon event detection.

### R5. Real-Time Alerting & Notification Engine
- Windows Native Toast: Real-time toast notifications on the Master PC (e.g. Alert: New user 'gamer123' created on 'LIVINGROOM-PC').
- Discord / Slack / Telegram Webhooks: Configurable multi-destination webhooks for mobile push alerts.
- In-dashboard audio/visual alert banner with ACK (acknowledge/dismiss) workflow.

## Acceptance Criteria

### Backend & Database
- [ ] SQLite database initializes cleanly with schema, indexes, and sample seed data if empty.
- [ ] Enrollment API requires a valid FleetKey; unauthorized requests return HTTP 401.
- [ ] Telemetry ingestion updates device status, hardware specs, and software list in O(1) transaction time.

### Web Dashboard
- [ ] Dashboard loads in modern browsers with zero console errors.
- [ ] Responsive dark-mode interface with glassmorphic cards, live status badges, and interactive tables.
- [ ] Dynamic device groups automatically evaluate node memberships based on telemetry properties.
- [ ] Application assignment matrix allows toggling Required/Prohibited/Available per group.

### Security Watchdog & Alerts
- [ ] Triggering simulated Event 4720 (User Created) or App Install immediately posts to /api/v1/nodes/events.
- [ ] Event shows up in the Dashboard Activity Feed within 2 seconds.
- [ ] Webhook notification payload is dispatched with device name, timestamp, and event details.

### Cloudflare Tunnel Integration
- [ ] Provides automatic cloudflared configuration generator and status check in the UI/CLI.
- [ ] Client agent seamlessly switches between direct LAN and Cloudflare Tunnel hostname.
