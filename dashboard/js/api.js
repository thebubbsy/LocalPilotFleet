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

/* ── Windows Update for Business & Update Rings ────────────────────── */
async function getUpdateRings() {
  return apiFetch('/api/v1/fleet/updates/rings');
}

async function getUpdateStats() {
  return apiFetch('/api/v1/fleet/updates/stats');
}

async function getUpdateRing(id) {
  return apiFetch(`/api/v1/fleet/updates/rings/${encodeURIComponent(id)}`);
}

async function createUpdateRing(data) {
  return apiFetch('/api/v1/fleet/updates/rings', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateUpdateRing(id, data) {
  return apiFetch(`/api/v1/fleet/updates/rings/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteUpdateRing(id) {
  return apiFetch(`/api/v1/fleet/updates/rings/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function scanDeviceUpdates(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/scan-updates`, {
    method: 'POST'
  });
}

async function getDeviceUpdateStatus(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/update-status`);
}

/* ── Device Compliance Policies & Conditional Access ───────────────── */
async function getCompliancePolicies() {
  return apiFetch('/api/v1/fleet/compliance/policies');
}

async function getComplianceStats() {
  return apiFetch('/api/v1/fleet/compliance/stats');
}

async function getCompliancePolicy(id) {
  return apiFetch(`/api/v1/fleet/compliance/policies/${encodeURIComponent(id)}`);
}

async function createCompliancePolicy(data) {
  return apiFetch('/api/v1/fleet/compliance/policies', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateCompliancePolicy(id, data) {
  return apiFetch(`/api/v1/fleet/compliance/policies/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteCompliancePolicy(id) {
  return apiFetch(`/api/v1/fleet/compliance/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getDeviceCompliance(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/compliance`);
}

async function evaluateDeviceCompliance(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/evaluate-compliance`, {
    method: 'POST'
  });
}

/* ── Application Management (Win32 & Winget) ────────────────────────── */
async function getApps() {
  return apiFetch('/api/v1/fleet/apps');
}

async function getAppStats() {
  return apiFetch('/api/v1/fleet/apps/stats');
}

async function getApp(id) {
  return apiFetch(`/api/v1/fleet/apps/${encodeURIComponent(id)}`);
}

async function createApp(data) {
  return apiFetch('/api/v1/fleet/apps', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateApp(id, data) {
  return apiFetch(`/api/v1/fleet/apps/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteApp(id) {
  return apiFetch(`/api/v1/fleet/apps/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getDeviceApps(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/apps`);
}

async function installDeviceApp(deviceId, appId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/apps/${encodeURIComponent(appId)}/install-now`, {
    method: 'POST'
  });
}

/* ── Endpoint Security & Microsoft Defender Antivirus ────────────────── */
async function getSecurityPolicies() {
  return apiFetch('/api/v1/fleet/security/policies');
}

async function getSecurityPolicy(id) {
  return apiFetch(`/api/v1/fleet/security/policies/${encodeURIComponent(id)}`);
}

async function createSecurityPolicy(data) {
  return apiFetch('/api/v1/fleet/security/policies', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateSecurityPolicy(id, data) {
  return apiFetch(`/api/v1/fleet/security/policies/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteSecurityPolicy(id) {
  return apiFetch(`/api/v1/fleet/security/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getSecurityStats() {
  return apiFetch('/api/v1/fleet/security/stats');
}

async function getAntivirusStatuses(params = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
  }
  const query = qs.toString() ? `?${qs}` : '';
  return apiFetch(`/api/v1/fleet/security/antivirus-status${query}`);
}

async function getSecurityThreats(params = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
  }
  const query = qs.toString() ? `?${qs}` : '';
  return apiFetch(`/api/v1/fleet/security/threats${query}`);
}

async function remediateThreat(id, status = 'RESOLVED') {
  return apiFetch(`/api/v1/fleet/security/threats/${encodeURIComponent(id)}/remediate`, {
    method: 'PATCH',
    body: JSON.stringify({ remediation_status: status })
  });
}

async function getDeviceSecurity(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/security`);
}

async function triggerSecurityScan(deviceId, scanType = 'QuickScan') {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/security/scan`, {
    method: 'POST',
    body: JSON.stringify({ scan_type: scanType })
  });
}

async function triggerSignatureUpdate(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/security/update-signatures`, {
    method: 'POST'
  });
}

/* ── BitLocker Drive Encryption & Recovery Vault ─────────────────────── */
async function getBitLockerStats() {
  return apiFetch('/api/v1/fleet/bitlocker/stats');
}

async function getBitLockerPolicies() {
  return apiFetch('/api/v1/fleet/bitlocker/policies');
}

async function getBitLockerPolicy(id) {
  return apiFetch(`/api/v1/fleet/bitlocker/policies/${encodeURIComponent(id)}`);
}

async function createBitLockerPolicy(data) {
  return apiFetch('/api/v1/fleet/bitlocker/policies', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateBitLockerPolicy(id, data) {
  return apiFetch(`/api/v1/fleet/bitlocker/policies/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteBitLockerPolicy(id) {
  return apiFetch(`/api/v1/fleet/bitlocker/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getBitLockerKeys(params = {}) {
  const qs = new URLSearchParams();
  if (params.device_id) qs.set('device_id', params.device_id);
  if (params.query) qs.set('query', params.query);
  if (params.limit) qs.set('limit', params.limit);
  if (params.offset) qs.set('offset', params.offset);
  const qStr = qs.toString();
  return apiFetch(`/api/v1/fleet/bitlocker/keys${qStr ? '?' + qStr : ''}`);
}

async function revealBitLockerKey(id, data = {}) {
  return apiFetch(`/api/v1/fleet/bitlocker/keys/${encodeURIComponent(id)}/reveal`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function getBitLockerAuditLogs(params = {}) {
  const qs = new URLSearchParams();
  if (params.device_id) qs.set('device_id', params.device_id);
  if (params.limit) qs.set('limit', params.limit);
  if (params.offset) qs.set('offset', params.offset);
  const qStr = qs.toString();
  return apiFetch(`/api/v1/fleet/bitlocker/audit${qStr ? '?' + qStr : ''}`);
}

async function getDeviceBitLocker(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/bitlocker`);
}

async function rotateDeviceBitLockerKey(deviceId, data = {}) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/bitlocker/rotate-keys`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function enableDeviceBitLocker(deviceId, data = {}) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/bitlocker/enable`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function backupDeviceBitLockerKeys(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/bitlocker/backup-keys`, {
    method: 'POST'
  });
}

/* ── Windows LAPS (Local Administrator Password Solution) ────────── */

async function getLapsStats() {
  return apiFetch('/api/v1/fleet/laps/stats');
}

async function getLapsPolicies() {
  return apiFetch('/api/v1/fleet/laps/policies');
}

async function getLapsPolicy(id) {
  return apiFetch(`/api/v1/fleet/laps/policies/${encodeURIComponent(id)}`);
}

async function createLapsPolicy(data) {
  return apiFetch('/api/v1/fleet/laps/policies', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateLapsPolicy(id, data) {
  return apiFetch(`/api/v1/fleet/laps/policies/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteLapsPolicy(id) {
  return apiFetch(`/api/v1/fleet/laps/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getLapsPasswords(params = {}) {
  const qs = new URLSearchParams();
  if (params.query) qs.set('query', params.query);
  if (params.status) qs.set('status', params.status);
  const qStr = qs.toString();
  return apiFetch(`/api/v1/fleet/laps/passwords${qStr ? '?' + qStr : ''}`);
}

async function getDeviceLaps(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/laps`);
}

async function revealLapsPassword(deviceId, data = {}) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/laps/reveal`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function revealHistoricalLapsPassword(historyId, data = {}) {
  return apiFetch(`/api/v1/fleet/laps/history/${encodeURIComponent(historyId)}/reveal`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function rotateDeviceLapsPassword(deviceId, data = {}) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/laps/rotate`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function getLapsAuditLogs(params = {}) {
  const qs = new URLSearchParams();
  if (params.limit) qs.set('limit', params.limit);
  const qStr = qs.toString();
  return apiFetch(`/api/v1/fleet/laps/audit${qStr ? '?' + qStr : ''}`);
}

/* ── Endpoint Privilege Management (EPM) ─────────────────────────── */

async function getEpmStats() {
  return apiFetch('/api/v1/fleet/epm/stats');
}

async function getEpmPolicies() {
  return apiFetch('/api/v1/fleet/epm/policies');
}

async function getEpmPolicy(id) {
  return apiFetch(`/api/v1/fleet/epm/policies/${encodeURIComponent(id)}`);
}

async function createEpmPolicy(data) {
  return apiFetch('/api/v1/fleet/epm/policies', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateEpmPolicy(id, data) {
  return apiFetch(`/api/v1/fleet/epm/policies/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteEpmPolicy(id) {
  return apiFetch(`/api/v1/fleet/epm/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getEpmRules(params = {}) {
  const qs = new URLSearchParams();
  if (params.policy_id) qs.set('policy_id', params.policy_id);
  if (params.elevation_type) qs.set('elevation_type', params.elevation_type);
  if (params.search) qs.set('search', params.search);
  const qStr = qs.toString();
  return apiFetch(`/api/v1/fleet/epm/rules${qStr ? '?' + qStr : ''}`);
}

async function getEpmRule(id) {
  return apiFetch(`/api/v1/fleet/epm/rules/${encodeURIComponent(id)}`);
}

async function createEpmRule(data) {
  return apiFetch('/api/v1/fleet/epm/rules', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function updateEpmRule(id, data) {
  return apiFetch(`/api/v1/fleet/epm/rules/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
}

async function deleteEpmRule(id) {
  return apiFetch(`/api/v1/fleet/epm/rules/${encodeURIComponent(id)}`, {
    method: 'DELETE'
  });
}

async function getEpmRequests(params = {}) {
  const qs = new URLSearchParams();
  if (params.device_id) qs.set('device_id', params.device_id);
  if (params.status) qs.set('status', params.status);
  if (params.limit) qs.set('limit', params.limit);
  const qStr = qs.toString();
  return apiFetch(`/api/v1/fleet/epm/requests${qStr ? '?' + qStr : ''}`);
}

async function reviewEpmRequest(id, data = {}) {
  return apiFetch(`/api/v1/fleet/epm/requests/${encodeURIComponent(id)}/review`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

async function getEpmElevationLogs(params = {}) {
  const qs = new URLSearchParams();
  if (params.device_id) qs.set('device_id', params.device_id);
  if (params.limit) qs.set('limit', params.limit);
  const qStr = qs.toString();
  return apiFetch(`/api/v1/fleet/epm/logs${qStr ? '?' + qStr : ''}`);
}

async function getDeviceEpm(deviceId) {
  return apiFetch(`/api/v1/fleet/devices/${encodeURIComponent(deviceId)}/epm`);
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
  // Windows Update for Business & Update Rings
  getUpdateRings,
  getUpdateStats,
  getUpdateRing,
  createUpdateRing,
  updateUpdateRing,
  deleteUpdateRing,
  scanDeviceUpdates,
  getDeviceUpdateStatus,
  // Device Compliance & Zero-Trust Policies
  getCompliancePolicies,
  getComplianceStats,
  getCompliancePolicy,
  createCompliancePolicy,
  updateCompliancePolicy,
  deleteCompliancePolicy,
  getDeviceCompliance,
  evaluateDeviceCompliance,
  // Application Management & Win32/Winget Packaging
  getApps,
  getAppStats,
  getApp,
  createApp,
  updateApp,
  deleteApp,
  getDeviceApps,
  installDeviceApp,
  // Endpoint Security & Defender Antivirus
  getSecurityPolicies,
  getSecurityPolicy,
  createSecurityPolicy,
  updateSecurityPolicy,
  deleteSecurityPolicy,
  getSecurityStats,
  getAntivirusStatuses,
  getSecurityThreats,
  remediateThreat,
  getDeviceSecurity,
  triggerSecurityScan,
  triggerSignatureUpdate,
  // BitLocker Drive Encryption & Recovery Vault
  getBitLockerStats,
  getBitLockerPolicies,
  getBitLockerPolicy,
  createBitLockerPolicy,
  updateBitLockerPolicy,
  deleteBitLockerPolicy,
  getBitLockerKeys,
  revealBitLockerKey,
  getBitLockerAuditLogs,
  getDeviceBitLocker,
  rotateDeviceBitLockerKey,
  enableDeviceBitLocker,
  backupDeviceBitLockerKeys,
  // Windows LAPS (Local Administrator Password Solution)
  getLapsStats,
  getLapsPolicies,
  getLapsPolicy,
  createLapsPolicy,
  updateLapsPolicy,
  deleteLapsPolicy,
  getLapsPasswords,
  getDeviceLaps,
  revealLapsPassword,
  revealHistoricalLapsPassword,
  rotateDeviceLapsPassword,
  getLapsAuditLogs,
  // Endpoint Privilege Management (EPM)
  getEpmStats,
  getEpmPolicies,
  getEpmPolicy,
  createEpmPolicy,
  updateEpmPolicy,
  deleteEpmPolicy,
  getEpmRules,
  getEpmRule,
  createEpmRule,
  updateEpmRule,
  deleteEpmRule,
  getEpmRequests,
  reviewEpmRequest,
  getEpmElevationLogs,
  getDeviceEpm,
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
