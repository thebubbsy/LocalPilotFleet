/**
 * LocalPilot Fleet — REST API Client
 * dashboard/js/api.js
 *
 * Reads FLEET_KEY and SERVER_URL from localStorage.
 * All methods return parsed JSON or throw on HTTP error.
 */

/* ── Config helpers ────────────────────────────────────────────────── */
function getServerUrl() {
  return (localStorage.getItem('fleet_server_url') || '').replace(/\/$/, '') || window.location.origin;
}

function getFleetKey() {
  return localStorage.getItem('fleet_key') || '';
}

/**
 * Core fetch wrapper.
 * @param {string} path
 * @param {RequestInit} [options]
 * @returns {Promise<any>}
 */
async function apiFetch(path, options = {}) {
  const base = getServerUrl();
  const key  = getFleetKey();

  const headers = {
    'Content-Type': 'application/json',
    'X-Fleet-Key': key,
    ...(options.headers || {})
  };

  const res = await fetch(`${base}${path}`, {
    ...options,
    headers
  });

  // Handle non-JSON responses (e.g. 204 No Content)
  if (res.status === 204) return null;

  let body;
  try {
    body = await res.json();
  } catch {
    body = { error: 'PARSE_ERROR', message: `HTTP ${res.status} — non-JSON response` };
  }

  if (!res.ok) {
    const msg = body?.message || body?.error || `HTTP ${res.status}`;
    const err = new Error(msg);
    err.status  = res.status;
    err.body    = body;
    throw err;
  }

  return body;
}

/* ── Fleet Stats ────────────────────────────────────────────────────── */
async function getFleetStats() {
  return apiFetch('/api/v1/fleet/stats');
}

/* ── Devices ────────────────────────────────────────────────────────── */
async function getDevices(params = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
  }
  const query = qs.toString() ? `?${qs}` : '';
  return apiFetch(`/api/v1/fleet/devices${query}`);
}

async function getDevice(id) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(id)}`);
}

async function updateDevice(id, data) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteDevice(id) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

/* ── Groups ─────────────────────────────────────────────────────────── */
async function getGroups() {
  return apiFetch('/api/v1/fleet/groups');
}

async function createGroup(data) {
  return apiFetch('/api/v1/fleet/groups', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function deleteGroup(id) {
  return apiFetch(`/api/v1/fleet/groups/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function evaluateGroupRule(rule_syntax) {
  return apiFetch('/api/v1/fleet/groups/evaluate', {
    method: 'POST',
    body: JSON.stringify({ rule_syntax })
  });
}

/* ── Software Catalog ───────────────────────────────────────────────── */
async function getSoftwareCatalog() {
  return apiFetch('/api/v1/fleet/software');
}

async function addSoftwareEntry(data) {
  return apiFetch('/api/v1/fleet/software', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateSoftwareEntry(id, data) {
  return apiFetch(`/api/v1/fleet/software/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteSoftwareEntry(id) {
  return apiFetch(`/api/v1/fleet/software/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

/* ── Policies ───────────────────────────────────────────────────────── */
async function getPolicies() {
  return apiFetch('/api/v1/fleet/policies');
}

async function setPolicyAssignment(data) {
  return apiFetch('/api/v1/fleet/policies', {
    method: 'PUT',
    body: JSON.stringify(data)
  });
}

/* ── Events ─────────────────────────────────────────────────────────── */
async function getEvents(params = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
  }
  const query = qs.toString() ? `?${qs}` : '';
  return apiFetch(`/api/v1/fleet/events${query}`);
}

async function acknowledgeEvent(id) {
  return apiFetch(`/api/v1/fleet/events/${encodeURIComponent(id)}/ack`, {
    method: 'POST',
    body: JSON.stringify({ acknowledged_by: 'Fleet Admin' })
  });
}

/* ── Settings ───────────────────────────────────────────────────────── */
async function getSettings() {
  return apiFetch('/api/v1/fleet/settings');
}

async function updateSettings(data) {
  return apiFetch('/api/v1/fleet/settings', {
    method: 'PUT',
    body: JSON.stringify(data)
  });
}

/* ── Tunnel ─────────────────────────────────────────────────────────── */
async function getTunnelStatus() {
  return apiFetch('/api/v1/fleet/tunnel/status');
}

async function generateTunnelConfig(hostname) {
  return apiFetch('/api/v1/fleet/tunnel/generate', {
    method: 'POST',
    body: JSON.stringify({ hostname })
  });
}

/* ── Credential helpers ─────────────────────────────────────────────── */
function saveCredentials(serverUrl, fleetKey) {
  localStorage.setItem('fleet_server_url', serverUrl);
  localStorage.setItem('fleet_key', fleetKey);
}

function clearCredentials() {
  localStorage.removeItem('fleet_server_url');
  localStorage.removeItem('fleet_key');
}

function hasCredentials() {
  return Boolean(getFleetKey());
}

/**
 * Verify credentials by calling health + stats endpoint.
 * @returns {Promise<boolean>}
 */
async function verifyCredentials() {
  try {
    await getFleetStats();
    return true;
  } catch {
    return false;
  }
}

/* ── Remote Scripts & Cloud Shell ─────────────────────────────────── */
async function runScript(deviceId, script) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/run-script`, {
    method: 'POST',
    body: JSON.stringify({ script })
  });
}

async function getCommandStatus(commandId) {
  return apiFetch(`/api/v1/fleet/commands/${encodeURIComponent(commandId)}`);
}

async function getDeviceCommands(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/commands`);
}

/* ── Proactive Remediations ────────────────────────────────────────── */
async function getRemediations() {
  return apiFetch('/api/v1/fleet/remediations');
}

async function getRemediationStats() {
  return apiFetch('/api/v1/fleet/remediations/stats');
}

async function getRemediationDetails(id) {
  return apiFetch(`/api/v1/fleet/remediations/${encodeURIComponent(id)}`);
}

async function createRemediation(data) {
  return apiFetch('/api/v1/fleet/remediations', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateRemediation(id, data) {
  return apiFetch(`/api/v1/fleet/remediations/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteRemediation(id) {
  return apiFetch(`/api/v1/fleet/remediations/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function runRemediationNow(id) {
  return apiFetch(`/api/v1/fleet/remediations/${encodeURIComponent(id)}/run-now`, {
    method: 'POST'
  });
}

/* ── Configuration Profiles ─────────────────────────────────────────── */
async function getProfiles() {
  return apiFetch('/api/v1/fleet/profiles');
}

async function getProfileStats() {
  return apiFetch('/api/v1/fleet/profiles/stats');
}

async function getSettingsCatalog() {
  return apiFetch('/api/v1/fleet/profiles/catalog');
}

async function getProfile(id) {
  return apiFetch(`/api/v1/fleet/profiles/${encodeURIComponent(id)}`);
}

async function createProfile(data) {
  return apiFetch('/api/v1/fleet/profiles', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateProfile(id, data) {
  return apiFetch(`/api/v1/fleet/profiles/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteProfile(id) {
  return apiFetch(`/api/v1/fleet/profiles/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getDeviceProfiles(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/profiles`);
}

/* ── Exports ──────────────────────────────────────────────────────────
   Attach everything to window.FleetAPI for consumption by other modules
   ──────────────────────────────────────────────────────────────────── */
window.FleetAPI = {
  getServerUrl,
  getFleetKey,
  saveCredentials,
  clearCredentials,
  hasCredentials,
  verifyCredentials,
  // Devices
  getFleetStats,
  getDevices,
  getDevice,
  updateDevice,
  deleteDevice,
  // Remote Scripts & Cloud Shell
  runScript,
  getCommandStatus,
  getDeviceCommands,
  // Proactive Remediations
  getRemediations,
  getRemediationStats,
  getRemediationDetails,
  createRemediation,
  updateRemediation,
  deleteRemediation,
  runRemediationNow,
  // Configuration Profiles
  getProfiles,
  getProfileStats,
  getSettingsCatalog,
  getProfile,
  createProfile,
  updateProfile,
  deleteProfile,
  getDeviceProfiles,
  // Groups
  getGroups,
  createGroup,
  deleteGroup,
  evaluateGroupRule,
  // Software
  getSoftwareCatalog,
  addSoftwareEntry,
  updateSoftwareEntry,
  deleteSoftwareEntry,
  // Policies
  getPolicies,
  setPolicyAssignment,
  // Events
  getEvents,
  acknowledgeEvent,
  // Settings
  getSettings,
  updateSettings,
  // Tunnel
  getTunnelStatus,
  generateTunnelConfig
};
// Append window.apiFetch and aliases to api.js
window.apiFetch = apiFetch;
window.renderKpiCards = () => {
  if (window.KpiCards) window.KpiCards.refresh();
  if (window.OverviewWidgets) window.OverviewWidgets.render();
};
