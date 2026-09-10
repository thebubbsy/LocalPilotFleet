#!/usr/bin/env bash
# =============================================================================
# LocalPilot Fleet — macOS Lightweight Unified Endpoint Management (UEM) Agent
# agent/enroll-macos.sh
# =============================================================================
# Usage:
#   sudo ./enroll-macos.sh --server https://fleet.localpilot.internal:8443 --fleet-key YOUR_KEY
# =============================================================================

set -e

SERVER_URL=""
FLEET_KEY=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --server) SERVER_URL="$2"; shift ;;
        --fleet-key) FLEET_KEY="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [[ -z "$SERVER_URL" || -z "$FLEET_KEY" ]]; then
    echo "Error: --server and --fleet-key are mandatory."
    echo "Usage: sudo $0 --server <url> --fleet-key <key>"
    exit 1
fi

echo "🍏 [LocalPilot Fleet] Initiating macOS UEM Node Enrollment..."

# 1. Gather System Telemetry
HOSTNAME=$(scutil --get ComputerName 2>/dev/null || hostname)
SERIAL=$(ioreg -l | grep IOPlatformSerialNumber | awk -F'"' '{print $4}' || echo "UNKNOWN-SERIAL")
UUID=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $(NF-1)}' || uuidgen)
OS_NAME="macOS"
OS_VERSION=$(sw_vers -productVersion)
OS_BUILD=$(sw_vers -buildVersion)
ARCH=$(uname -m)
CPU_MODEL=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")
RAM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo "8589934592")
PRIMARY_USER=$(stat -f "%Su" /dev/console 2>/dev/null || whoami)

# Check FileVault & SIP
FILEVAULT_STATUS=$(fdesetup status 2>/dev/null || echo "FileVault is Off.")
SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")

echo "📊 Telemetry Collected:"
echo "   Host: $HOSTNAME ($SERIAL)"
echo "   OS:   $OS_NAME $OS_VERSION (Build $OS_BUILD, $ARCH)"
echo "   CPU:  $CPU_MODEL"
echo "   User: $PRIMARY_USER"

# 2. Submit Enrollment Payload
PAYLOAD=$(cat <<EOF
{
  "hostname": "$HOSTNAME",
  "serial_number": "$SERIAL",
  "uuid": "$UUID",
  "os_name": "$OS_NAME",
  "os_version": "$OS_VERSION",
  "os_build": "$OS_BUILD",
  "os_architecture": "$ARCH",
  "cpu_model": "$CPU_MODEL",
  "total_ram_bytes": $RAM_BYTES,
  "primary_user": "$PRIMARY_USER",
  "agent_version": "2.0.0-macos"
}
EOF
)

RESPONSE=$(curl -s -k -X POST "$SERVER_URL/api/v1/nodes/enroll/mobile" \
  -H "Content-Type: application/json" \
  -H "x-fleet-key: $FLEET_KEY" \
  -d "$PAYLOAD")

echo "✅ Enrollment Response: $RESPONSE"

DEVICE_ID=$(echo "$RESPONSE" | grep -o '"device_id":"[^"]*' | cut -d'"' -f4 || echo "")
TOKEN=$(echo "$RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4 || echo "")

if [[ -n "$DEVICE_ID" && -n "$TOKEN" ]]; then
    CONFIG_DIR="/Library/Application Support/LocalPilot"
    mkdir -p "$CONFIG_DIR"
    cat <<EOF > "$CONFIG_DIR/node.conf"
DEVICE_ID=$DEVICE_ID
NODE_TOKEN=$TOKEN
SERVER_URL=$SERVER_URL
ENROLLED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
    chmod 600 "$CONFIG_DIR/node.conf"
    echo "🎉 macOS endpoint enrolled successfully as $DEVICE_ID!"
else
    echo "⚠️ Enrollment completed but tokens could not be parsed."
fi
