# LocalPilot Fleet Command Center

> **Zero-cloud Intune-style device management for your family fleet, homelab, and personal workstations. You are the IT admin. These are your devices. You deserve to know everything.**

[![Node.js](https://img.shields.io/badge/Node.js-26%2B-brightgreen?logo=node.js)](https://nodejs.org/)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.x-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![cloudflared](https://img.shields.io/badge/cloudflared-2026.8.3-orange)](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)

---

## Why LocalPilot Fleet?

Microsoft Intune costs ~$8/device/month and requires Azure AD. JAMF starts at thousands of dollars. Every enterprise MDM solution is designed for corporate IT departments managing hundreds of strangers' devices — not for **you**, managing the 4 PCs in your house, your dad's laptop, or a homelab cluster.

LocalPilot Fleet is the MDM you actually want:

- **100% on-premises** — your data never leaves your network
- **Zero subscription** — no Azure, no cloud, no monthly bill
- **Full telemetry** — hardware fingerprints, uptime, disk health, security events
- **Real-time** — Server-Sent Events push live updates to your dashboard
- **Remote-capable** — Cloudflare Tunnel bridges roaming devices to your Command Center without port-forwarding or VPN setup
- **Yours** — MIT licensed, readable code, no tracking, no telemetry sent anywhere

---

## Architecture

```
                         LocalPilot Fleet — System Diagram
  ─────────────────────────────────────────────────────────────────────────

    COMMAND CENTER (Daddy PC / Homelab Server)
  ┌──────────────────────────────────────────────────────────────────┐
  │  Start-LocalPilotFleet.ps1                                        │
  │  └─► node server/src/index.js --port 8443                        │
  │       ├── REST API  /api/v1/*   (FleetKey Bearer auth)           │
  │       ├── SSE       /api/v1/events  (real-time push)             │
  │       ├── SQLite    server/data/fleet.db  (WAL mode)             │
  │       └── Dashboard ./dashboard/index.html (SPA)                 │
  │                                                                   │
  │  cloudflare/                                                      │
  │  └─► cloudflared tunnel run  ──────────────────────────────────┐ │
  └────────────────────────┬───────────────────────────────────────┼─┘
                           │                                        │
           LAN (10.1.1.x)  │                          Cloudflare   │
  ─────────────────────────┼──────────────────────    Edge Network  │
                           │                                        │
    MANAGED LAN DEVICES    │               ROAMING DEVICES         │
  ┌────────────────────┐   │           ┌────────────────────────┐   │
  │  DESKTOP-A         │   │           │  Laptop (coffee shop)  │   │
  │  Install-LocalPilot│◄──┤           │  Install-LocalPilotNode│◄──┘
  │  Node.ps1          │   │           │  -ServerUrl https://   │
  │  ├── Telemetry     │   │           │    fleet.onyachamp.com │
  │  ├── Heartbeat     │   │           │  ├── Telemetry         │
  │  └── Event watcher │   │           │  └── Heartbeat         │
  └────────────────────┘   │           └────────────────────────┘
                           │
  ┌────────────────────┐   │
  │  DESKTOP-B / NAS   │◄──┘
  │  Install-LocalPilot│
  │  Node.ps1          │
  └────────────────────┘

  Connectivity resolution (Test-HybridResolver.ps1):
    1. Try  http://DADDY-PC:8443/api/v1/health   (3 s timeout, LAN)
    2. Fallback https://fleet.onyachamp.com/api/v1/health  (Tunnel)
    3. Report: Route='lan'|'tunnel'|'offline', Latency_ms, ServerVersion
```

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Node.js | 18+ (26 recommended) | [nodejs.org](https://nodejs.org) |
| PowerShell | 5.1+ (7.x recommended) | Built-in on Windows |
| cloudflared | Any (2026.8.3 tested) | Optional — remote device support only |

### 1. Start the Command Center

Open PowerShell in the LocalPilot Fleet directory and run:

```powershell
.\Start-LocalPilotFleet.ps1
```

On first run, a secure **FleetKey** is generated automatically and saved to `fleet-config.json`. Write it down — you need it to enroll devices.

```
+============================================================+
|  FIRST RUN -- YOUR FLEET KEY HAS BEEN GENERATED           |
|                                                            |
|  Fleet Key: a1b2c3d4-e5f6-7890-abcd-ef1234567890         |
|                                                            |
|  Save this key! You need it to enroll managed devices.    |
+============================================================+
```

The dashboard opens automatically at **http://localhost:8443**.

Custom port / key:
```powershell
.\Start-LocalPilotFleet.ps1 -Port 9443 -FleetKey 'my-custom-key' -NoBrowser
```

---

### 2. Enroll a Managed Device

Run this on each PC you want to manage (in an elevated PowerShell prompt):

```powershell
.\agent\Install-LocalPilotNode.ps1 `
    -ServerUrl http://DADDY-PC:8443 `
    -FleetKey  a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

For roaming devices off the LAN, use the Cloudflare Tunnel URL instead:

```powershell
.\agent\Install-LocalPilotNode.ps1 `
    -ServerUrl https://fleet.yourdomain.com `
    -FleetKey  a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

---

### 3. Open the Dashboard

```
http://localhost:8443
```

No login required on the LAN — the FleetKey is the authentication layer for API calls. The dashboard auto-discovers enrolled devices within seconds of them checking in.

---

## Features

| Feature | Description |
|---------|-------------|
| **Device Inventory** | Hardware fingerprint: CPU, RAM, serial number, OS build, drives |
| **Real-Time Heartbeat** | Every managed node pings in — see online/offline status live via SSE |
| **Security Event Watch** | Monitors Windows Security log for user account changes (Event 4720/4726/4728/4732) |
| **Disk Health** | Drive usage, free space alerts, S.M.A.R.T. status |
| **Application Policy** | Track which apps are installed fleet-wide |
| **Remote Connectivity** | Cloudflare Tunnel bridges LAN + roaming devices transparently |
| **Hybrid Resolver** | Auto-selects lowest-latency route (LAN vs Tunnel) per device |
| **SQLite WAL Engine** | Fast, concurrent, file-based — no database server required |
| **Zero Dependencies** | Node.js 26 built-in `node:sqlite` — nothing to `npm install` |
| **REST API** | Full JSON API at `/api/v1/*` for scripting and integration |
| **Server-Sent Events** | Live event stream at `/api/v1/events` for real-time dashboard updates |
| **FleetKey Auth** | Bearer token authentication on all API endpoints |
| **Windows Firewall & Sentinel** | Stateful inbound/outbound rules, profile governance (Domain/Private/Public), and live listening socket perimeter sentinel |

---

## Fleet Security Model

LocalPilot Fleet uses a **pre-shared key** model appropriate for a personal/family fleet where you control every device.

### FleetKey

- Generated on first run using `RandomNumberGenerator` (cryptographically random UUID)
- Stored in `fleet-config.json` (keep this file private)
- All agent-to-server communication uses the key as a `Bearer` token:
  ```
  Authorization: Bearer a1b2c3d4-e5f6-7890-abcd-ef1234567890
  ```

### Network Security

| Scenario | Security |
|----------|----------|
| LAN (same network) | FleetKey Bearer auth; no TLS required on trusted LAN |
| Cloudflare Tunnel | TLS terminated at Cloudflare edge; tunnel is encrypted end-to-end |
| Public Internet (no tunnel) | **Not supported** — never expose port 8443 directly to the internet |

### What LocalPilot Fleet Does NOT Do

- Does not phone home or send any telemetry outside your network
- Does not require cloud accounts, email, or registration
- Does not store passwords or credentials (FleetKey is the only secret)
- Does not modify remote devices without explicit administrator consent

---

## Cloudflare Tunnel (for remote devices)

Use Cloudflare Tunnel to manage devices that roam off your home network without opening firewall ports.

### Setup

**Step 1** — Generate the tunnel config:
```powershell
.\cloudflare\Generate-TunnelConfig.ps1 -Hostname fleet.onyachamp.com
```

**Step 2** — Authenticate with Cloudflare (one-time, opens browser):
```powershell
& 'C:\Program Files (x86)\cloudflared\cloudflared.exe' login
```

**Step 3** — Create the tunnel:
```powershell
& 'C:\Program Files (x86)\cloudflared\cloudflared.exe' tunnel create localpilot-fleet
# Output: Created tunnel localpilot-fleet with id 151f6973-811e-4c64-8ddc-f0bb59c367ff
```

**Step 4** — Populate `cloudflare/config.yml` with the tunnel ID and origin credentials file path.

**Step 5** — Route your DNS:
```powershell
& 'C:\Program Files (x86)\cloudflared\cloudflared.exe' tunnel route dns localpilot-fleet fleet.onyachamp.com
```

**Step 6** — Run the tunnel (foreground test):
```powershell
& 'C:\Program Files (x86)\cloudflared\cloudflared.exe' tunnel --config cloudflare\config.yml run localpilot-fleet
```

**Step 7** — Install as a Windows Service for persistent operation:
```powershell
# Run as Administrator
.\cloudflare\Install-CloudflaredService.ps1
```

### Test Connectivity (Hybrid LAN / Cloudflare Resolver)

```powershell
.\cloudflare\Test-HybridResolver.ps1 `
    -LanUrl    http://localhost:8443 `
    -TunnelUrl https://fleet.onyachamp.com `
    -FleetKey  <YOUR-FLEET-KEY>
```

Output when on LAN:
```
  LocalPilot Fleet -- Hybrid Connectivity Resolver
  ------------------------------------------------
  [~]   LAN URL    : http://localhost:8443
  [~]   Tunnel URL : https://fleet.onyachamp.com

  [~]   Probing LAN route (3 s timeout)...
  [OK]  LAN route active (low latency) -- 2148 ms  |  server: LocalPilot Fleet Server

Route Latency_ms ServerVersion
----- ---------- -------------
lan         2148 LocalPilot Fleet Server
```

Output when roaming off-LAN (automatic Cloudflare Tunnel fallback):
```
  [~]   LAN URL    : http://10.1.1.213:8443
  [~]   Tunnel URL : https://fleet.onyachamp.com

  [~]   Probing LAN route (3 s timeout)...
  [XX]  LAN unreachable (3033 ms). Trying Cloudflare Tunnel...
  [~]   Probing Tunnel route (10 s timeout)...
  [OK]  Tunnel route active -- 173 ms  |  server: LocalPilot Fleet Server
  [!!]  Using tunnel path -- expect higher latency than LAN.

Route  Latency_ms ServerVersion
-----  ---------- -------------
tunnel        173 LocalPilot Fleet Server
```

---

## Project Structure

```
LocalPilotFleet/
├── Start-LocalPilotFleet.ps1        # One-command server launcher
├── fleet-config.json                # Runtime config + FleetKey (auto-created)
├── package.json                     # Node.js project descriptor
│
├── server/
│   ├── src/
│   │   ├── index.js                 # HTTP server entrypoint & CLI flag parser
│   │   ├── db.js                    # SQLite WAL engine (node:sqlite)
│   │   ├── utils/
│   │   │   ├── router.js            # Lightweight HTTP router
│   │   │   ├── auth.js              # FleetKey Bearer token middleware
│   │   │   └── logger.js            # Structured console logger
│   │   └── routes/
│   │       ├── nodes.js             # Device node CRUD endpoints
│   │       ├── events.js            # SSE event stream + telemetry ingestion
│   │       └── fleet.js             # Fleet-wide summary & policy endpoints
│   └── data/
│       └── fleet.db                 # SQLite database (WAL mode, auto-created)
│
├── dashboard/
│   └── index.html                   # Single-page dashboard (dark mode SPA)
│
├── cloudflare/
│   ├── Generate-TunnelConfig.ps1    # Interactive tunnel setup generator
│   ├── config.yml                   # Generated tunnel config (after setup)
│   ├── config.sample.yml            # Annotated sample config
│   ├── Test-HybridResolver.ps1      # LAN/Tunnel connectivity tester
│   └── Install-CloudflaredService.ps1  # Persistent Windows Service installer
│
├── agent/
│   └── Install-LocalPilotNode.ps1   # Enroll a managed device
│
└── tests/
    ├── tier1_features.test.js
    ├── tier2_boundaries.test.js
    ├── tier3_pairwise.test.js
    └── tier4_realworld.test.js
```

---

## Server API Reference

All endpoints require `Authorization: Bearer <FleetKey>` except `/api/v1/health`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/v1/health` | Health check (no auth required) |
| `GET`  | `/api/v1/nodes` | List all enrolled devices |
| `GET`  | `/api/v1/nodes/:id` | Get a single device |
| `POST` | `/api/v1/nodes` | Register / update a device (called by agent) |
| `GET`  | `/api/v1/events` | SSE stream for real-time updates |
| `POST` | `/api/v1/events` | Ingest a telemetry event (called by agent) |
| `GET`  | `/api/v1/fleet` | Fleet-wide summary stats |

### Health Check Response

```json
{
  "status": "ok",
  "service": "LocalPilot Fleet Server",
  "timestamp": "2026-09-08T02:05:23.000Z",
  "uptime_seconds": 3600
}
```

---

## Configuration Reference

`fleet-config.json` (auto-created on first run):

```json
{
  "fleetKey":  "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "port":      8443,
  "dashboard": "C:\\temp\\LocalPilotFleet\\dashboard",
  "dbPath":    "C:\\temp\\LocalPilotFleet\\server\\data\\fleet.db",
  "createdAt": "2026-09-08T02:05:23.000+10:00",
  "version":   "1.0.0"
}
```

Environment variables override `fleet-config.json`:

| Variable | Description |
|----------|-------------|
| `PORT` | Server port |
| `FLEET_KEY` | FleetKey Bearer token |
| `DB_PATH` | SQLite database file path |
| `DASHBOARD_PATH` | Dashboard static files directory |

---

## Requirements

- **Windows 10/11** (build 19041+) — for agent WMI telemetry and WinRT notifications
- **Node.js 18+** — built-in `node:sqlite` requires Node 22+; Node 26 LTS recommended
- **PowerShell 5.1+** — PowerShell 7.x recommended for agent scripts
- **cloudflared** — optional; only needed for roaming device support

---

## License

MIT — Matthew Bubb / [OnYaChamp.com](https://onyachamp.com)

```
Copyright (c) 2026 Matthew Bubb

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
