import crypto from 'node:crypto';
import { createContractServer, DEFAULT_FLEET_KEY, evaluateRule } from './contract_server.js';

let sharedServerInstance = null;
let sharedBaseUrl = null;

/**
 * Setup test harness. If an external server is defined via process.env.FLEET_SERVER_URL,
 * uses that. Otherwise boots an in-process spec-compliant contract server.
 */
export async function setupTestEnvironment() {
  if (process.env.FLEET_SERVER_URL) {
    sharedBaseUrl = process.env.FLEET_SERVER_URL;
    return {
      baseUrl: sharedBaseUrl,
      isExternal: true,
      server: null
    };
  }

  if (!sharedServerInstance) {
    sharedServerInstance = createContractServer();
    const info = await sharedServerInstance.start(0);
    sharedBaseUrl = info.url;
  }

  return {
    baseUrl: sharedBaseUrl,
    isExternal: false,
    server: sharedServerInstance
  };
}

export async function teardownTestEnvironment() {
  if (sharedServerInstance) {
    await sharedServerInstance.stop();
    sharedServerInstance = null;
    sharedBaseUrl = null;
  }
}

export function getBaseUrl() {
  return sharedBaseUrl || process.env.FLEET_SERVER_URL || 'http://localhost:8443';
}

export function getFleetKey() {
  return process.env.FLEET_KEY || DEFAULT_FLEET_KEY;
}

export function getDispatchedAlerts() {
  if (sharedServerInstance) {
    return sharedServerInstance.dispatchedAlerts;
  }
  return { toasts: [], discord: [], slack: [], telegram: [], events: [] };
}

export function clearDispatchedAlerts() {
  if (sharedServerInstance) {
    sharedServerInstance.dispatchedAlerts.toasts.length = 0;
    sharedServerInstance.dispatchedAlerts.discord.length = 0;
    sharedServerInstance.dispatchedAlerts.slack.length = 0;
    sharedServerInstance.dispatchedAlerts.telegram.length = 0;
    sharedServerInstance.dispatchedAlerts.events.length = 0;
  }
}

/**
 * Helper to make HTTP request to LocalPilot Fleet server
 */
export async function apiRequest(endpoint, {
  method = 'GET',
  headers = {},
  body = null,
  fleetKey = null,
  nodeToken = null
} = {}) {
  const url = `${getBaseUrl()}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`;

  const reqHeaders = { ...headers };
  if (fleetKey) {
    reqHeaders['X-Fleet-Key'] = fleetKey;
  }
  if (nodeToken) {
    reqHeaders['Authorization'] = `Bearer ${nodeToken}`;
  }

  let reqBody = null;
  if (body !== null) {
    if (typeof body === 'object') {
      reqHeaders['Content-Type'] = reqHeaders['Content-Type'] || 'application/json';
      reqBody = JSON.stringify(body);
    } else {
      reqBody = String(body);
    }
  }

  const res = await fetch(url, {
    method,
    headers: reqHeaders,
    body: reqBody
  });

  let data = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    data = await res.text();
  }

  return {
    status: res.status,
    headers: res.headers,
    data,
    ok: res.ok
  };
}

/**
 * Enrolls a fresh test device and returns device credentials
 */
export async function enrollTestDevice(overrides = {}) {
  const suffix = crypto.randomBytes(4).toString('hex');
  const payload = createEnrollPayload({
    hostname: `TEST-NODE-${suffix}`,
    serial_number: `SN-${suffix}`,
    uuid: crypto.randomUUID(),
    mac_address: `00:15:5D:${suffix.slice(0, 2)}:${suffix.slice(2, 4)}:01`,
    ...overrides
  });

  const res = await apiRequest('/api/v1/nodes/enroll', {
    method: 'POST',
    fleetKey: getFleetKey(),
    body: payload
  });

  if (!res.ok) {
    throw new Error(`Failed to enroll test device: ${JSON.stringify(res.data)}`);
  }

  return {
    device_id: res.data.device_id,
    node_token: res.data.node_token,
    payload,
    response: res.data
  };
}

/**
 * Payload factories
 */
export function createEnrollPayload(overrides = {}) {
  const uuid = crypto.randomUUID();
  return {
    hostname: `DESKTOP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
    serial_number: `MB-${crypto.randomBytes(6).toString('hex').toUpperCase()}`,
    uuid,
    mac_address: '00:D8:61:3A:9F:12',
    friendly_name: 'Living Room Family PC',
    tags: ['family', 'livingroom', 'desktop'],
    os_name: 'Microsoft Windows 11 Home',
    os_version: '10.0.22631',
    os_build: '22631.3296',
    os_architecture: '64-bit',
    cpu_model: 'AMD Ryzen 5 5600G with Radeon Graphics',
    cpu_cores: 6,
    cpu_logical: 12,
    total_ram_bytes: 17179869184, // 16GB
    gpu_name: 'AMD Radeon Graphics',
    has_battery: false,
    tpm_present: true,
    tpm_version: '2.0',
    tpm_enabled: true,
    secure_boot_enabled: true,
    bitlocker_status: 'Disabled',
    primary_user: 'Dad',
    agent_version: '1.0.0',
    ...overrides
  };
}

export function createHeartbeatPayload(overrides = {}) {
  return {
    cpu_usage_percent: 14.5,
    ram_used_bytes: 8589934592,
    ram_free_bytes: 8589934592,
    ram_usage_percent: 50.0,
    battery_percent: 100.0,
    battery_charging: false,
    ip_address: '192.168.1.145',
    connection_route: 'LAN',
    uptime_seconds: 182390,
    ...overrides
  };
}

export function createTelemetryPayload(deviceId, overrides = {}) {
  return {
    device_id: deviceId,
    timestamp: new Date().toISOString(),
    hardware: {
      motherboard_serial: 'MB-98234190823',
      cpu_usage_percent: 8.2,
      ram_used_bytes: 6442450944,
      ram_free_bytes: 10737418240,
      ram_usage_percent: 37.5,
      disks: [
        {
          device_id: '\\\\.\\PHYSICALDRIVE0',
          drive_letter: 'C:',
          model: 'Samsung SSD 980 PRO 1TB',
          total_gb: 931.5,
          free_gb: 412.8,
          smart_status: 'Healthy',
          temperature_c: 38
        }
      ],
      network_adapters: [
        {
          name: 'Ethernet',
          mac: '00:D8:61:3A:9F:12',
          ip: '192.168.1.145',
          speed_mbps: 1000,
          status: 'Up'
        }
      ]
    },
    security: {
      tpm_present: true,
      tpm_version: '2.0',
      tpm_enabled: true,
      secure_boot_enabled: true,
      bitlocker_volumes: [
        {
          mount_point: 'C:',
          protection_status: 'Off',
          encryption_percentage: 0
        }
      ],
      local_users: [
        {
          username: 'Dad',
          full_name: 'Family Administrator',
          is_admin: true,
          is_disabled: false,
          password_required: true
        }
      ]
    },
    installed_software: [
      {
        name: 'Google Chrome',
        publisher: 'Google LLC',
        version: '122.0.6261.129',
        winget_id: 'Google.Chrome',
        install_type: 'Registry'
      }
    ],
    ...overrides
  };
}

export function createEventPayload(overrides = {}) {
  return {
    event_type: 'USER_CREATED',
    event_id: 4720,
    event_source: 'Security',
    severity: 'CRITICAL',
    summary: 'New local Windows user account created',
    timestamp: new Date().toISOString(),
    details: {
      TargetUserName: 'gamer123',
      TargetDomainName: 'WORKSTATION',
      SubjectUserName: 'Dad',
      SubjectUserSid: 'S-1-5-21-239482938-239482-1001'
    },
    ...overrides
  };
}

export { evaluateRule, DEFAULT_FLEET_KEY };
