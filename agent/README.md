# LocalPilot Fleet — Node Agent Setup Guide

> **Agent Version**: 1.0.0  
> **Target OS**: Windows 10 / 11 (any edition), Windows Server 2022/2025  
> **Shell**: PowerShell 5.1+ (Windows PowerShell) or PowerShell 7+

---

## 1. Prerequisites

| Requirement | Details |
|---|---|
| **PowerShell** | 5.1+ (built into Windows 10/11). PS7 recommended for best compatibility. |
| **Admin Rights** | `Install-LocalPilotNode.ps1` and `Uninstall-LocalPilotNode.ps1` must run as Administrator. |
| **Network** | The managed PC must reach the Fleet Command Center (LAN or Cloudflare Tunnel). |
| **Fleet Key** | The pre-shared `X-Fleet-Key` set on the server (default: `localpilot-secret-key-2026`). |
| **winget** (optional) | Required for PolicyCheck mode. Ships with Windows 11 and App Installer on Windows 10. |
| **Execution Policy** | Scheduled tasks run with `-ExecutionPolicy Bypass`. For manual runs, set to `RemoteSigned`. |

### Enable Execution Policy for Manual Runs

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

---

## 2. Installation

### Basic LAN Install (same local network as Daddy PC)

```powershell
# Run in an elevated (Administrator) PowerShell:
.\Install-LocalPilotNode.ps1 -FleetKey "localpilot-secret-key-2026"
```

### Full Install with All Options

```powershell
.\Install-LocalPilotNode.ps1 `
    -ServerUrl      "http://192.168.1.100:8443" `
    -FleetKey       "localpilot-secret-key-2026" `
    -DeviceName     "Sarah's Surface Laptop" `
    -Group          "family" `
    -CloudflareUrl  "https://fleet.yourdomain.com"
```

### Roaming Laptop (Cloudflare Tunnel Only)

```powershell
.\Install-LocalPilotNode.ps1 `
    -ServerUrl      "http://192.168.1.100:8443" `
    -FleetKey       "localpilot-secret-key-2026" `
    -DeviceName     "Kids Gaming Laptop" `
    -Group          "family" `
    -CloudflareUrl  "https://fleet.yourdomain.com"
```

> The agent always **tries LAN first** (5 s timeout), then falls back to Cloudflare. No manual switching needed.

---

## 3. What the Installer Does

1. Creates `C:\ProgramData\LocalPilotFleet\`
2. Enables Windows Security Auditing for user/group management events
3. Harvests full hardware fingerprint (CPU, RAM, GPU, TPM, BitLocker, SecureBoot)
4. POSTs to `POST /api/v1/nodes/enroll` with `X-Fleet-Key`
5. Saves the returned `node_token` and `device_id` to `config.json`
6. Locks `config.json` to SYSTEM + Administrators only
7. Copies all agent scripts to the install directory
8. Registers three Scheduled Tasks as `NT AUTHORITY\SYSTEM`

---

## 4. Scheduled Tasks

| Task Name | Trigger | Script | Purpose |
|---|---|---|---|
| `LocalPilot-Heartbeat` | Every **5 minutes** | `Invoke-LocalPilotAgent.ps1 -Mode Heartbeat` | Lightweight CPU/RAM/IP keepalive |
| `LocalPilot-Telemetry` | Every **30 minutes** | `Invoke-LocalPilotAgent.ps1 -Mode Telemetry` | Full hardware/software/user inventory |
| `LocalPilot-Watchdog` | Event-driven | `Watchdog-SecurityEvent.ps1` | Real-time security event dispatch |

### Watchdog Event Subscriptions

The Watchdog task fires within milliseconds of:

| Log | Event ID | Trigger |
|---|---|---|
| Security | **4720** | New local user account created |
| Security | **4726** | Local user account deleted |
| Security | **4728** | User added to global security group |
| Security | **4732** | User added to local security group (Administrators) |
| Application (MsiInstaller) | **1033** | MSI application install completed |
| Application (MsiInstaller) | **11707** | MSI product installed successfully |
| AppXDeployment-Server/Operational | **854** | Microsoft Store / AppX package installed |

---

## 5. Configuration File

**Location**: `C:\ProgramData\LocalPilotFleet\config.json`  
**Permissions**: SYSTEM + Administrators only (set by installer)

```json
{
  "device_id":              "c7a840e5-b169-42b7-a3f2-1f72d4cf9e31",
  "node_token":             "lp_node_6f0e9d1a3b5c7e8f9a0b2c4d6e8f...",
  "server_url":             "http://192.168.1.100:8443",
  "cloudflare_url":         "https://fleet.yourdomain.com",
  "active_server_url":      "http://192.168.1.100:8443",
  "hostname":               "LIVINGROOM-PC",
  "device_name":            "Living Room PC",
  "group":                  "family",
  "agent_version":          "1.0.0",
  "enrolled_at":            "2026-09-08T02:00:00.000+10:00",
  "heartbeat_interval_sec": 300,
  "telemetry_interval_min": 30
}
```

> ⚠️ **Never share `node_token`** — it is the device's authentication credential. Treat it like a password.

---

## 6. Manual Operation Commands

Run these manually for testing or on-demand operations. No admin needed (unless Telemetry needs TPM/BitLocker access).

### Force a Heartbeat

```powershell
& "C:\ProgramData\LocalPilotFleet\Invoke-LocalPilotAgent.ps1" -Mode Heartbeat
```

### Force a Full Telemetry Harvest

```powershell
& "C:\ProgramData\LocalPilotFleet\Invoke-LocalPilotAgent.ps1" -Mode Telemetry
```

### Run a Policy Check (installs/removes apps)

```powershell
& "C:\ProgramData\LocalPilotFleet\Invoke-LocalPilotAgent.ps1" -Mode PolicyCheck
```

### Run the Watchdog Manually

```powershell
& "C:\ProgramData\LocalPilotFleet\Watchdog-SecurityEvent.ps1"
```

---

## 7. Simulate Security Events (Dev/Test)

Use `Simulate-SecurityEvent.ps1` to test the full alert pipeline without triggering real OS events.

```powershell
# Simulate a new user created (reads config.json automatically):
.\Simulate-SecurityEvent.ps1 -EventType UserCreated

# Simulate privilege escalation:
.\Simulate-SecurityEvent.ps1 -EventType PrivilegeEscalation

# Simulate a prohibited app detection:
.\Simulate-SecurityEvent.ps1 -EventType AppProhibited -AppName "BitTorrent"

# Dry run — see payload without sending:
.\Simulate-SecurityEvent.ps1 -EventType SoftwareInstalled -DryRun

# Manual credentials (no config.json needed):
.\Simulate-SecurityEvent.ps1 `
    -EventType  UserCreated `
    -ServerUrl  "http://192.168.1.100:8443" `
    -DeviceId   "c7a840e5-b169-42b7-a3f2-1f72d4cf9e31" `
    -Token      "lp_node_..." `
    -Username   "testuser99"
```

### Event Types Available

| `-EventType` | `event_type` Sent | Severity | Windows Event ID |
|---|---|---|---|
| `UserCreated` | `USER_CREATED` | HIGH | 4720 |
| `UserDeleted` | `USER_DELETED` | MEDIUM | 4726 |
| `PrivilegeEscalation` | `ADMIN_ADDED` | CRITICAL | 4732 |
| `SoftwareInstalled` | `APP_INSTALLED` | MEDIUM | 1033 |
| `AppProhibited` | `APP_PROHIBITED_DETECTED` | CRITICAL | 1033 |

---

## 8. Uninstallation

### Remove Agent Only (keep device on Fleet dashboard)

```powershell
.\Uninstall-LocalPilotNode.ps1 -Force
```

### Remove Agent AND Remove from Fleet Dashboard

```powershell
.\Uninstall-LocalPilotNode.ps1 `
    -Deregister `
    -FleetKey "localpilot-secret-key-2026" `
    -Force
```

The uninstaller:
- Stops and removes all three Scheduled Tasks
- Deletes `C:\ProgramData\LocalPilotFleet\` (including token and logs)
- Optionally calls `DELETE /api/v1/fleet/devices/{device_id}` to remove the device record

---

## 9. Log Files

| File | Purpose |
|---|---|
| `C:\ProgramData\LocalPilotFleet\install.log` | Installation trace |
| `C:\ProgramData\LocalPilotFleet\agent.log` | Heartbeat/Telemetry/PolicyCheck run log |
| `C:\ProgramData\LocalPilotFleet\watchdog.log` | Watchdog event dispatch log (auto-rotated at 10 MB) |

View live agent log:

```powershell
Get-Content "C:\ProgramData\LocalPilotFleet\agent.log" -Wait -Tail 20
```

---

## 10. Troubleshooting

### "This script must be run as Administrator"

Right-click PowerShell → **Run as Administrator**, then re-run the script.

### "Enrollment failed" — Cannot reach the server

1. Verify the Fleet server is running: `curl http://192.168.1.100:8443/api/v1/health`
2. Check Windows Firewall allows port 8443 inbound on the server PC
3. Try with `-CloudflareUrl` if the server is on a different network

### Heartbeat task not appearing in Task Scheduler

1. Open Task Scheduler → Task Scheduler Library
2. Look for `LocalPilot-Heartbeat`, `LocalPilot-Telemetry`, `LocalPilot-Watchdog`
3. If missing, re-run `Install-LocalPilotNode.ps1` (it's idempotent)

### "INVALID_NODE_TOKEN" error in logs

The `node_token` in `config.json` doesn't match the server's `node_token_hash`. This can happen if:
- The server database was reset
- The node was re-enrolled and the old config file wasn't updated

**Fix**: Re-run `Install-LocalPilotNode.ps1` — it will update the token.

### PolicyCheck: "winget not found"

Install the **App Installer** package from the Microsoft Store, or via:

```powershell
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
```

### Watchdog fires but no Security events appear

Ensure Windows Security Auditing is enabled. The installer does this automatically, but verify with:

```powershell
auditpol /get /subcategory:"User Account Management"
# Should show: Success and Failure
```

If not enabled, run as Administrator:

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

---

## 11. Architecture Notes

- **Zero idle RAM**: Agent scripts run and exit — no persistent background process.
- **Dual-mode routing**: LAN → Cloudflare Tunnel automatic failover in all modes.
- **Auth**: Enrollment uses `X-Fleet-Key`; all subsequent calls use `Authorization: Bearer <node_token>`.
- **Security**: `config.json` permissions are locked to SYSTEM + Administrators via ACL.
- **Idempotent install**: Re-running the installer re-enrolls the node and refreshes the token.

---

*LocalPilot Fleet — Zero-cloud, zero-idle, privacy-first fleet management for your homelab.*
