import crypto from 'crypto';

/**
 * Enterprise Application Management & Company Portal Engine
 * Provides enterprise app catalog management, private WinGet software distribution,
 * self-service Company Portal request workflows, elevation approvals, and license seat allocations.
 */

/**
 * Retrieves aggregate statistics for Enterprise Application Management.
 */
export function getCatalogStats(db) {
  const totalApps = db.prepare('SELECT COUNT(*) as cnt FROM enterprise_app_catalog').get().cnt;
  const featuredApps = db.prepare('SELECT COUNT(*) as cnt FROM enterprise_app_catalog WHERE featured = 1').get().cnt;
  const selfServiceApps = db.prepare('SELECT COUNT(*) as cnt FROM enterprise_app_catalog WHERE self_service_enabled = 1').get().cnt;
  
  const licenseStats = db.prepare(`
    SELECT 
      COALESCE(SUM(total_licenses), 0) as total_licenses
    FROM enterprise_app_catalog
  `).get();
  
  const allocatedLicenses = db.prepare(`
    SELECT COUNT(*) as cnt FROM app_license_allocations WHERE status = 'ACTIVE'
  `).get().cnt;

  const totalLicenses = licenseStats.total_licenses || 0;
  const availableLicenses = Math.max(0, totalLicenses - allocatedLicenses);

  const pendingRequests = db.prepare(`
    SELECT COUNT(*) as cnt FROM company_portal_requests WHERE status = 'PENDING_APPROVAL'
  `).get().cnt;

  const queuedInstalls = db.prepare(`
    SELECT COUNT(*) as cnt FROM company_portal_requests WHERE status IN ('QUEUED', 'INSTALLING')
  `).get().cnt;

  const completedInstalls = db.prepare(`
    SELECT COUNT(*) as cnt FROM company_portal_requests WHERE status = 'COMPLETED'
  `).get().cnt;

  const categories = db.prepare(`
    SELECT category, COUNT(*) as count 
    FROM enterprise_app_catalog 
    GROUP BY category 
    ORDER BY count DESC
  `).all();

  return {
    total_apps: totalApps,
    featured_apps: featuredApps,
    self_service_apps: selfServiceApps,
    total_licenses: totalLicenses,
    allocated_licenses: allocatedLicenses,
    available_licenses: availableLicenses,
    pending_requests: pendingRequests,
    queued_installs: queuedInstalls,
    completed_installs: completedInstalls,
    categories
  };
}

/**
 * Retrieves enterprise catalog apps with optional filtering.
 */
export function getCatalogApps(db, filters = {}) {
  let query = `
    SELECT 
      a.*,
      (SELECT COUNT(*) FROM app_license_allocations l WHERE l.catalog_app_id = a.id AND l.status = 'ACTIVE') as allocated_licenses,
      (SELECT COUNT(*) FROM company_portal_requests r WHERE r.catalog_app_id = a.id AND r.status = 'COMPLETED') as install_count,
      (SELECT COUNT(*) FROM company_portal_requests r WHERE r.catalog_app_id = a.id AND r.status = 'PENDING_APPROVAL') as pending_requests
    FROM enterprise_app_catalog a
    WHERE 1=1
  `;
  const params = [];

  if (filters.category) {
    query += ' AND a.category = ?';
    params.push(filters.category);
  }

  if (filters.self_service_enabled !== undefined && filters.self_service_enabled !== null) {
    query += ' AND a.self_service_enabled = ?';
    params.push(filters.self_service_enabled ? 1 : 0);
  }

  if (filters.featured !== undefined && filters.featured !== null) {
    query += ' AND a.featured = ?';
    params.push(filters.featured ? 1 : 0);
  }

  if (filters.license_type) {
    query += ' AND a.license_type = ?';
    params.push(filters.license_type);
  }

  if (filters.search) {
    query += ' AND (a.name LIKE ? OR a.publisher LIKE ? OR a.package_identifier LIKE ?)';
    const term = `%${filters.search}%`;
    params.push(term, term, term);
  }

  query += ' ORDER BY a.featured DESC, a.name ASC';

  const rows = db.prepare(query).all(...params);
  return rows.map(app => {
    const total = app.total_licenses || 0;
    const allocated = app.allocated_licenses || 0;
    return {
      ...app,
      available_licenses: total > 0 ? Math.max(0, total - allocated) : 'UNLIMITED',
      license_utilization_pct: total > 0 ? Math.round((allocated / total) * 100) : 0
    };
  });
}

/**
 * Retrieves a single catalog app by ID with detailed allocations and requests.
 */
export function getCatalogApp(db, id) {
  const app = db.prepare('SELECT * FROM enterprise_app_catalog WHERE id = ?').get(id);
  if (!app) return null;

  const allocations = db.prepare(`
    SELECT l.*, d.hostname, d.serial_number
    FROM app_license_allocations l
    LEFT JOIN devices d ON d.id = l.device_id
    WHERE l.catalog_app_id = ?
    ORDER BY l.allocated_at DESC
  `).all(id);

  const requests = db.prepare(`
    SELECT r.*, d.hostname, d.serial_number
    FROM company_portal_requests r
    LEFT JOIN devices d ON d.id = r.device_id
    WHERE r.catalog_app_id = ?
    ORDER BY r.requested_at DESC
    LIMIT 20
  `).all(id);

  const allocatedCount = allocations.filter(a => a.status === 'ACTIVE').length;
  const total = app.total_licenses || 0;

  return {
    ...app,
    allocated_licenses: allocatedCount,
    available_licenses: total > 0 ? Math.max(0, total - allocatedCount) : 'UNLIMITED',
    license_utilization_pct: total > 0 ? Math.round((allocatedCount / total) * 100) : 0,
    allocations,
    recent_requests: requests
  };
}

/**
 * Creates a new enterprise application catalog entry.
 */
export function createCatalogApp(db, data) {
  if (!data.name || !data.publisher || !data.package_identifier || !data.version) {
    throw new Error('Name, publisher, package_identifier, and version are required.');
  }

  const validSources = ['WINGET', 'MSI', 'EXE', 'INTERNAL_STORE'];
  const sourceType = data.source_type && validSources.includes(data.source_type.toUpperCase())
    ? data.source_type.toUpperCase()
    : 'WINGET';

  const validLicenses = ['FREE', 'OPEN_SOURCE', 'PER_DEVICE', 'PER_USER', 'ENTERPRISE_SUBSCRIPTION'];
  const licenseType = data.license_type && validLicenses.includes(data.license_type.toUpperCase())
    ? data.license_type.toUpperCase()
    : 'FREE';

  const id = data.id || `app-${crypto.randomUUID().slice(0, 8)}`;
  const silentInstallArgs = data.silent_install_args !== undefined && data.silent_install_args !== null
    ? data.silent_install_args
    : '--silent --accept-package-agreements --accept-source-agreements';
  const silentUninstallArgs = data.silent_uninstall_args !== undefined && data.silent_uninstall_args !== null
    ? data.silent_uninstall_args
    : '--silent';

  const insert = db.prepare(`
    INSERT INTO enterprise_app_catalog (
      id, name, publisher, category, version, package_identifier,
      source_type, download_url, silent_install_args, silent_uninstall_args,
      icon_url, featured, self_service_enabled, license_type, total_licenses,
      assigned_group_id, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'), DATETIME('now'))
  `);

  insert.run(
    id,
    data.name.trim(),
    data.publisher.trim(),
    data.category ? data.category.trim() : 'General',
    data.version.trim(),
    data.package_identifier.trim(),
    sourceType,
    data.download_url || '',
    silentInstallArgs,
    silentUninstallArgs,
    data.icon_url || '',
    data.featured ? 1 : 0,
    data.self_service_enabled !== undefined ? (data.self_service_enabled ? 1 : 0) : 1,
    licenseType,
    parseInt(data.total_licenses, 10) || 0,
    data.assigned_group_id || null
  );

  return getCatalogApp(db, id);
}

/**
 * Updates an enterprise catalog application.
 */
export function updateCatalogApp(db, id, data) {
  const existing = db.prepare('SELECT * FROM enterprise_app_catalog WHERE id = ?').get(id);
  if (!existing) return null;

  const validSources = ['WINGET', 'MSI', 'EXE', 'INTERNAL_STORE'];
  const sourceType = data.source_type && validSources.includes(data.source_type.toUpperCase())
    ? data.source_type.toUpperCase()
    : existing.source_type;

  const validLicenses = ['FREE', 'OPEN_SOURCE', 'PER_DEVICE', 'PER_USER', 'ENTERPRISE_SUBSCRIPTION'];
  const licenseType = data.license_type && validLicenses.includes(data.license_type.toUpperCase())
    ? data.license_type.toUpperCase()
    : existing.license_type;

  const update = db.prepare(`
    UPDATE enterprise_app_catalog SET
      name = ?,
      publisher = ?,
      category = ?,
      version = ?,
      package_identifier = ?,
      source_type = ?,
      download_url = ?,
      silent_install_args = ?,
      silent_uninstall_args = ?,
      icon_url = ?,
      featured = ?,
      self_service_enabled = ?,
      license_type = ?,
      total_licenses = ?,
      assigned_group_id = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `);

  update.run(
    data.name !== undefined ? data.name.trim() : existing.name,
    data.publisher !== undefined ? data.publisher.trim() : existing.publisher,
    data.category !== undefined ? data.category.trim() : existing.category,
    data.version !== undefined ? data.version.trim() : existing.version,
    data.package_identifier !== undefined ? data.package_identifier.trim() : existing.package_identifier,
    sourceType,
    data.download_url !== undefined ? data.download_url : existing.download_url,
    data.silent_install_args !== undefined ? data.silent_install_args : existing.silent_install_args,
    data.silent_uninstall_args !== undefined ? data.silent_uninstall_args : existing.silent_uninstall_args,
    data.icon_url !== undefined ? data.icon_url : existing.icon_url,
    data.featured !== undefined ? (data.featured ? 1 : 0) : existing.featured,
    data.self_service_enabled !== undefined ? (data.self_service_enabled ? 1 : 0) : existing.self_service_enabled,
    licenseType,
    data.total_licenses !== undefined ? parseInt(data.total_licenses, 10) : existing.total_licenses,
    data.assigned_group_id !== undefined ? data.assigned_group_id : existing.assigned_group_id,
    id
  );

  return getCatalogApp(db, id);
}

/**
 * Deletes an enterprise catalog application and its cascades.
 */
export function deleteCatalogApp(db, id) {
  const existing = db.prepare('SELECT id FROM enterprise_app_catalog WHERE id = ?').get(id);
  if (!existing) return false;

  db.prepare('DELETE FROM enterprise_app_catalog WHERE id = ?').run(id);
  return true;
}

/**
 * Retrieves the Company Portal view for a specific client device.
 */
export function getCompanyPortalCatalog(db, deviceId) {
  const apps = db.prepare(`
    SELECT a.*
    FROM enterprise_app_catalog a
    WHERE a.self_service_enabled = 1
    ORDER BY a.featured DESC, a.name ASC
  `).all();

  const requests = db.prepare(`
    SELECT * FROM company_portal_requests 
    WHERE device_id = ? 
    ORDER BY requested_at DESC
  `).all(deviceId);

  const allocations = db.prepare(`
    SELECT * FROM app_license_allocations 
    WHERE device_id = ? AND status = 'ACTIVE'
  `).all(deviceId);

  return apps.map(app => {
    const appRequest = requests.find(r => r.catalog_app_id === app.id);
    const appAllocation = allocations.find(l => l.catalog_app_id === app.id);

    return {
      ...app,
      installation_status: appRequest ? appRequest.status : 'NOT_INSTALLED',
      active_request_id: appRequest ? appRequest.id : null,
      license_allocated: !!appAllocation,
      license_key: appAllocation ? appAllocation.license_key : null
    };
  });
}

/**
 * Retrieves company portal requests with optional filtering.
 */
export function getCompanyPortalRequests(db, filters = {}) {
  let query = `
    SELECT 
      r.*,
      a.name as app_name,
      a.publisher as app_publisher,
      a.package_identifier,
      a.icon_url,
      a.version as app_version,
      a.license_type,
      d.hostname,
      d.serial_number
    FROM company_portal_requests r
    JOIN enterprise_app_catalog a ON a.id = r.catalog_app_id
    JOIN devices d ON d.id = r.device_id
    WHERE 1=1
  `;
  const params = [];

  if (filters.status) {
    query += ' AND r.status = ?';
    params.push(filters.status);
  }

  if (filters.device_id) {
    query += ' AND r.device_id = ?';
    params.push(filters.device_id);
  }

  if (filters.catalog_app_id) {
    query += ' AND r.catalog_app_id = ?';
    params.push(filters.catalog_app_id);
  }

  if (filters.search) {
    query += ' AND (a.name LIKE ? OR d.hostname LIKE ? OR r.user_name LIKE ?)';
    const term = `%${filters.search}%`;
    params.push(term, term, term);
  }

  query += ' ORDER BY r.requested_at DESC';

  return db.prepare(query).all(...params);
}

/**
 * Submits a new self-service Company Portal installation or uninstallation request.
 */
export function createCompanyPortalRequest(db, data) {
  if (!data.catalog_app_id || !data.device_id) {
    throw new Error('catalog_app_id and device_id are required.');
  }

  const app = db.prepare('SELECT * FROM enterprise_app_catalog WHERE id = ?').get(data.catalog_app_id);
  if (!app) {
    throw new Error(`Enterprise application ${data.catalog_app_id} not found.`);
  }

  const device = db.prepare('SELECT id, hostname FROM devices WHERE id = ?').get(data.device_id);
  if (!device) {
    throw new Error(`Device ${data.device_id} not found.`);
  }

  const requestType = data.request_type && ['INSTALL', 'UNINSTALL', 'REPAIR'].includes(data.request_type.toUpperCase())
    ? data.request_type.toUpperCase()
    : 'INSTALL';

  const isPaidLicense = ['PER_DEVICE', 'PER_USER', 'ENTERPRISE_SUBSCRIPTION'].includes(app.license_type);
  let approvalRequired = data.approval_required !== undefined ? (data.approval_required ? 1 : 0) : (isPaidLicense ? 1 : 0);

  if (isPaidLicense && requestType === 'INSTALL' && app.total_licenses > 0) {
    const activeAllocations = db.prepare(`
      SELECT COUNT(*) as cnt FROM app_license_allocations 
      WHERE catalog_app_id = ? AND status = 'ACTIVE'
    `).get(app.id).cnt;

    if (activeAllocations >= app.total_licenses) {
      const existingSeat = db.prepare(`
        SELECT id FROM app_license_allocations 
        WHERE catalog_app_id = ? AND device_id = ? AND status = 'ACTIVE'
      `).get(app.id, device.id);

      if (!existingSeat) {
        throw new Error(`No available license seats for ${app.name} (${activeAllocations}/${app.total_licenses} allocated).`);
      }
    }
  }

  const id = data.id || `req-${crypto.randomUUID().slice(0, 8)}`;
  const status = approvalRequired ? 'PENDING_APPROVAL' : 'QUEUED';
  const approverUser = approvalRequired ? '' : 'AutoApproved';
  const userName = data.user_name || 'Current User';

  const insert = db.prepare(`
    INSERT INTO company_portal_requests (
      id, catalog_app_id, device_id, user_name, request_type,
      status, approval_required, approver_user, justification,
      error_message, requested_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', DATETIME('now'), DATETIME('now'), DATETIME('now'))
  `);

  insert.run(
    id,
    app.id,
    device.id,
    userName,
    requestType,
    status,
    approvalRequired,
    approverUser,
    data.justification || ''
  );

  if (status === 'QUEUED' && isPaidLicense && requestType === 'INSTALL') {
    const existingLic = db.prepare(`
      SELECT id FROM app_license_allocations 
      WHERE catalog_app_id = ? AND device_id = ? AND status = 'ACTIVE'
    `).get(app.id, device.id);

    if (!existingLic) {
      allocateLicense(db, {
        catalog_app_id: app.id,
        device_id: device.id,
        user_name: userName,
        license_key: `KEY-${crypto.randomUUID().slice(0, 8).toUpperCase()}`
      });
    }
  }

  return db.prepare(`
    SELECT r.*, a.name as app_name, a.package_identifier, d.hostname
    FROM company_portal_requests r
    JOIN enterprise_app_catalog a ON a.id = r.catalog_app_id
    JOIN devices d ON d.id = r.device_id
    WHERE r.id = ?
  `).get(id);
}

/**
 * Reviews (approves or rejects) a pending Company Portal request.
 */
export function reviewCompanyPortalRequest(db, requestId, reviewData) {
  const req = db.prepare('SELECT * FROM company_portal_requests WHERE id = ?').get(requestId);
  if (!req) {
    throw new Error(`Request ${requestId} not found.`);
  }

  const action = (reviewData.action || '').toUpperCase();
  if (!['APPROVE', 'REJECT'].includes(action)) {
    throw new Error('Action must be APPROVE or REJECT.');
  }

  const approver = reviewData.approver_user || 'IT Administrator';
  const notes = reviewData.notes || '';

  if (action === 'APPROVE') {
    const app = db.prepare('SELECT * FROM enterprise_app_catalog WHERE id = ?').get(req.catalog_app_id);
    if (app && ['PER_DEVICE', 'PER_USER', 'ENTERPRISE_SUBSCRIPTION'].includes(app.license_type)) {
      const existingLic = db.prepare(`
        SELECT id FROM app_license_allocations 
        WHERE catalog_app_id = ? AND device_id = ? AND status = 'ACTIVE'
      `).get(app.id, req.device_id);

      if (!existingLic) {
        allocateLicense(db, {
          catalog_app_id: app.id,
          device_id: req.device_id,
          user_name: req.user_name,
          license_key: `KEY-${crypto.randomUUID().slice(0, 8).toUpperCase()}`
        });
      }
    }

    db.prepare(`
      UPDATE company_portal_requests SET
        status = 'QUEUED',
        approver_user = ?,
        resolved_at = DATETIME('now'),
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(approver, requestId);
  } else {
    db.prepare(`
      UPDATE company_portal_requests SET
        status = 'REJECTED',
        approver_user = ?,
        error_message = ?,
        resolved_at = DATETIME('now'),
        updated_at = DATETIME('now')
      WHERE id = ?
    `).run(approver, notes || 'Request was rejected by IT administrator.', requestId);
  }

  return db.prepare('SELECT * FROM company_portal_requests WHERE id = ?').get(requestId);
}

/**
 * Updates execution status of a Company Portal request (typically called by node agent).
 */
export function updateCompanyPortalRequestStatus(db, requestId, statusData) {
  const req = db.prepare('SELECT * FROM company_portal_requests WHERE id = ?').get(requestId);
  if (!req) return null;

  const validStatuses = ['QUEUED', 'INSTALLING', 'COMPLETED', 'FAILED'];
  const status = statusData.status && validStatuses.includes(statusData.status.toUpperCase())
    ? statusData.status.toUpperCase()
    : req.status;

  const isTerminal = ['COMPLETED', 'FAILED'].includes(status);
  const resolvedAt = isTerminal ? new Date().toISOString().replace('T', ' ').substring(0, 19) : req.resolved_at;

  db.prepare(`
    UPDATE company_portal_requests SET
      status = ?,
      error_message = ?,
      resolved_at = ?,
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(
    status,
    statusData.error_message !== undefined ? statusData.error_message : req.error_message,
    resolvedAt,
    requestId
  );

  return db.prepare('SELECT * FROM company_portal_requests WHERE id = ?').get(requestId);
}

/**
 * Allocates a software license seat to a device or user.
 */
export function allocateLicense(db, data) {
  if (!data.catalog_app_id || !data.device_id) {
    throw new Error('catalog_app_id and device_id are required.');
  }

  const app = db.prepare('SELECT * FROM enterprise_app_catalog WHERE id = ?').get(data.catalog_app_id);
  if (!app) {
    throw new Error(`Enterprise application ${data.catalog_app_id} not found.`);
  }

  if (app.total_licenses > 0) {
    const activeCount = db.prepare(`
      SELECT COUNT(*) as cnt FROM app_license_allocations 
      WHERE catalog_app_id = ? AND status = 'ACTIVE'
    `).get(app.id).cnt;

    if (activeCount >= app.total_licenses) {
      throw new Error(`License limit reached for ${app.name} (${activeCount}/${app.total_licenses}).`);
    }
  }

  const id = data.id || `lic-${crypto.randomUUID().slice(0, 8)}`;
  const key = data.license_key || `KEY-${crypto.randomUUID().slice(0, 12).toUpperCase()}`;

  const insert = db.prepare(`
    INSERT INTO app_license_allocations (
      id, catalog_app_id, device_id, user_name, license_key,
      status, allocated_at, expires_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', DATETIME('now'), ?, DATETIME('now'), DATETIME('now'))
  `);

  insert.run(
    id,
    app.id,
    data.device_id,
    data.user_name || 'Assigned User',
    key,
    data.expires_at || null
  );

  return db.prepare('SELECT * FROM app_license_allocations WHERE id = ?').get(id);
}

/**
 * Revokes an existing software license allocation.
 */
export function revokeLicense(db, allocationId) {
  const existing = db.prepare('SELECT id FROM app_license_allocations WHERE id = ?').get(allocationId);
  if (!existing) return false;

  db.prepare(`
    UPDATE app_license_allocations SET
      status = 'REVOKED',
      updated_at = DATETIME('now')
    WHERE id = ?
  `).run(allocationId);

  return true;
}

/**
 * Retrieves all software license allocations with joined app and device info.
 */
export function getLicenseAllocations(db, filters = {}) {
  let query = `
    SELECT 
      l.*,
      a.name as app_name,
      a.publisher as app_publisher,
      a.version as app_version,
      a.license_type,
      d.hostname,
      d.serial_number
    FROM app_license_allocations l
    JOIN enterprise_app_catalog a ON a.id = l.catalog_app_id
    JOIN devices d ON d.id = l.device_id
    WHERE 1=1
  `;
  const params = [];

  if (filters.status) {
    query += ' AND l.status = ?';
    params.push(filters.status);
  }

  if (filters.catalog_app_id) {
    query += ' AND l.catalog_app_id = ?';
    params.push(filters.catalog_app_id);
  }

  if (filters.device_id) {
    query += ' AND l.device_id = ?';
    params.push(filters.device_id);
  }

  query += ' ORDER BY l.allocated_at DESC';

  return db.prepare(query).all(...params);
}

/**
 * Retrieves pending installation / uninstallation jobs for a device (for heartbeat consumption).
 */
export function getPendingDeviceInstalls(db, deviceId) {
  const requests = db.prepare(`
    SELECT 
      r.id as request_id,
      r.catalog_app_id,
      r.request_type,
      r.user_name,
      a.name as app_name,
      a.publisher,
      a.version,
      a.package_identifier,
      a.source_type,
      a.silent_install_args,
      a.silent_uninstall_args,
      a.download_url
    FROM company_portal_requests r
    JOIN enterprise_app_catalog a ON a.id = r.catalog_app_id
    WHERE r.device_id = ? AND r.status = 'QUEUED'
    ORDER BY r.requested_at ASC
  `).all(deviceId);

  return requests.map(req => {
    return {
      ...req,
      execution_script: generateWinGetScript(req, req.request_type)
    };
  });
}

/**
 * Generates production-grade PowerShell execution script for WinGet installation/uninstallation.
 */
export function generateWinGetScript(app, requestType = 'INSTALL') {
  const pkgId = app.package_identifier;
  const isUninstall = requestType && requestType.toUpperCase() === 'UNINSTALL';

  if (isUninstall) {
    const args = app.silent_uninstall_args || '--silent';
    return `# Enterprise App Management - WinGet Silent Uninstall
$ErrorActionPreference = 'Stop'
$pkgId = '${pkgId}'
Write-Host "Initiating silent uninstallation of $pkgId..." -ForegroundColor Cyan

try {
    $wingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        throw "WinGet executable not found in PATH or Windows Package Manager is not installed."
    }
    
    $proc = Start-Process winget.exe -ArgumentList "uninstall --id $pkgId ${args}" -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 2316632065) {
        Write-Host "Uninstallation of $pkgId succeeded (ExitCode: $($proc.ExitCode))." -ForegroundColor Green
        return @{ Success = $true; ExitCode = $proc.ExitCode }
    } else {
        throw "WinGet uninstallation failed with exit code $($proc.ExitCode)."
    }
} catch {
    Write-Error "Failed to uninstall $pkgId: $($_.Exception.Message)"
    return @{ Success = $false; Error = $_.Exception.Message }
}
`;
  }

  const args = app.silent_install_args || '--silent --accept-package-agreements --accept-source-agreements';
  return `# Enterprise App Management - WinGet Silent Automated Install
$ErrorActionPreference = 'Stop'
$pkgId = '${pkgId}'
Write-Host "Initiating automated installation of enterprise package $pkgId..." -ForegroundColor Cyan

try {
    $wingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        throw "WinGet executable not found in PATH or Windows Package Manager is not installed."
    }

    $proc = Start-Process winget.exe -ArgumentList "install --id $pkgId ${args}" -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 2316632065) {
        Write-Host "Installation of $pkgId completed successfully (ExitCode: $($proc.ExitCode))." -ForegroundColor Green
        return @{ Success = $true; ExitCode = $proc.ExitCode }
    } else {
        throw "WinGet installation failed with exit code $($proc.ExitCode)."
    }
} catch {
    Write-Error "Failed to install $pkgId: $($_.Exception.Message)"
    return @{ Success = $false; Error = $_.Exception.Message }
}
`;
}
