/**
 * LocalPilot Fleet — Declarative Policy & Compliance Engine
 * server/src/services/policyEngine.js
 *
 * Resolves effective group policies (Required, Prohibited, Available).
 * Enforces Prohibited > Required > Available security hierarchy.
 * Calculates compliance status (Compliant vs Drifted) and synthesizes Winget remediation commands.
 */

export function normalizeSoftwareName(name) {
  if (!name || typeof name !== 'string') return '';
  return name
    .toLowerCase()
    .replace(/\s*\([^)]*\)/g, '')             // remove (x64), (x86)
    .replace(/\s+v?[0-9]+(\.[0-9]+)*.*/g, '') // remove trailing versions
    .trim();
}

export function isSoftwareInstalled(catalogItem, installedSoftwareList) {
  if (!Array.isArray(installedSoftwareList) || installedSoftwareList.length === 0) {
    return { installed: false, matchedItem: null };
  }

  const catWinget = (catalogItem.winget_id || '').toLowerCase().trim();
  const catName = (catalogItem.name || '').toLowerCase().trim();
  const catNormName = normalizeSoftwareName(catalogItem.name);

  // Tier 1: Match by Winget ID
  if (catWinget) {
    for (const inst of installedSoftwareList) {
      const instWinget = (typeof inst === 'string' ? '' : (inst.winget_id || '')).toLowerCase().trim();
      if (instWinget && instWinget === catWinget) {
        return { installed: true, matchedItem: inst };
      }
    }
  }

  // Tier 2: Match by Exact Name
  for (const inst of installedSoftwareList) {
    const instName = (typeof inst === 'string' ? inst : (inst.name || '')).toLowerCase().trim();
    if (instName && instName === catName) {
      return { installed: true, matchedItem: inst };
    }
  }

  // Tier 3: Match by Normalized Name Substring
  for (const inst of installedSoftwareList) {
    const rawName = typeof inst === 'string' ? inst : (inst.name || '');
    const instNorm = normalizeSoftwareName(rawName);
    if (instNorm && catNormName && (instNorm === catNormName || instNorm.startsWith(catNormName) || catNormName.startsWith(instNorm))) {
      return { installed: true, matchedItem: inst };
    }
  }

  return { installed: false, matchedItem: null };
}

export const policyEngine = {
  getEffectivePolicyForDevice(db, deviceId) {
    // 1. Fetch assigned groups for this device
    const groupsStmt = db.prepare(`
      SELECT g.id, g.name, g.priority
      FROM dynamic_groups g
      JOIN group_memberships m ON g.id = m.group_id
      WHERE m.device_id = ?
      ORDER BY g.priority ASC
    `);
    const groups = groupsStmt.all(deviceId);

    if (!groups || groups.length === 0) {
      return {
        device_id: deviceId,
        assigned_groups: [],
        policies: { required: [], prohibited: [], available: [] }
      };
    }

    const groupIds = groups.map(g => g.id);
    const placeholders = groupIds.map(() => '?').join(',');

    // 2. Fetch all policy assignments joined with software catalog
    const policiesStmt = db.prepare(`
      SELECT 
        pa.group_id,
        pa.assignment_type,
        pa.auto_update,
        s.id AS software_id,
        s.name,
        s.publisher,
        s.winget_id,
        s.version,
        s.silent_install_args,
        s.silent_uninstall_args
      FROM policy_assignments pa
      JOIN software_catalog s ON pa.software_id = s.id
      WHERE pa.group_id IN (${placeholders})
    `);
    const rows = policiesStmt.all(...groupIds);

    // 3. Resolve conflicts: Prohibited > Required > Available
    const resolvedMap = new Map();

    for (const row of rows) {
      const existing = resolvedMap.get(row.software_id);
      const incomingType = row.assignment_type;

      if (!existing) {
        resolvedMap.set(row.software_id, {
          software: {
            software_id: row.software_id,
            name: row.name,
            publisher: row.publisher,
            winget_id: row.winget_id,
            version: row.version,
            silent_install_args: row.silent_install_args,
            silent_uninstall_args: row.silent_uninstall_args,
            auto_update: Boolean(row.auto_update)
          },
          assignment_type: incomingType
        });
        continue;
      }

      if (existing.assignment_type === 'Prohibited') {
        // Prohibited always takes precedence
        continue;
      } else if (incomingType === 'Prohibited') {
        existing.assignment_type = 'Prohibited';
      } else if (existing.assignment_type === 'Required') {
        continue;
      } else if (incomingType === 'Required') {
        existing.assignment_type = 'Required';
      }
    }

    const required = [];
    const prohibited = [];
    const available = [];

    for (const item of resolvedMap.values()) {
      if (item.assignment_type === 'Required') {
        required.push(item.software);
      } else if (item.assignment_type === 'Prohibited') {
        prohibited.push(item.software);
      } else if (item.assignment_type === 'Available') {
        available.push(item.software);
      }
    }

    return {
      device_id: deviceId,
      assigned_groups: groups.map(g => ({ id: g.id, name: g.name })),
      policies: { required, prohibited, available }
    };
  },

  evaluateCompliance(effectivePolicy, installedSoftwareList = []) {
    const policies = effectivePolicy.policies || { required: [], prohibited: [], available: [] };
    const missingRequired = [];
    const detectedProhibited = [];
    const driftReasons = [];
    const remediationActions = [];

    // Check Required Packages
    for (const pkg of policies.required) {
      const check = isSoftwareInstalled(pkg, installedSoftwareList);
      if (!check.installed) {
        missingRequired.push(pkg);
        driftReasons.push(`Missing required package '${pkg.name}' (${pkg.winget_id})`);

        const installArgs = pkg.silent_install_args || '--silent --accept-package-agreements --accept-source-agreements';
        remediationActions.push({
          action: 'install',
          package_id: pkg.software_id,
          name: pkg.name,
          winget_id: pkg.winget_id,
          command: `winget install --id "${pkg.winget_id}" --exact ${installArgs}`,
          reason: `Required package '${pkg.name}' is missing`
        });
      }
    }

    // Check Prohibited Packages
    for (const pkg of policies.prohibited) {
      const check = isSoftwareInstalled(pkg, installedSoftwareList);
      if (check.installed) {
        const item = check.matchedItem || {};
        detectedProhibited.push({ package: pkg, installed: item });
        driftReasons.push(`Prohibited package detected '${item.name || pkg.name}' (${pkg.winget_id})`);

        const uninstallArgs = pkg.silent_uninstall_args || '--silent';
        remediationActions.push({
          action: 'uninstall',
          package_id: pkg.software_id,
          name: pkg.name,
          winget_id: pkg.winget_id,
          command: `winget uninstall --id "${pkg.winget_id}" --exact ${uninstallArgs}`,
          reason: `Prohibited package '${pkg.name}' is installed`
        });
      }
    }

    const isCompliant = (missingRequired.length === 0 && detectedProhibited.length === 0);

    return {
      compliance_status: isCompliant ? 'Compliant' : 'Drifted',
      is_compliant: isCompliant,
      missing_required: missingRequired,
      detected_prohibited: detectedProhibited,
      drift_reasons: driftReasons,
      remediation_actions: remediationActions
    };
  },

  evaluateAndPersistDeviceCompliance(db, deviceId, installedSoftwareList = []) {
    const effectivePolicy = this.getEffectivePolicyForDevice(db, deviceId);
    const compliance = this.evaluateCompliance(effectivePolicy, installedSoftwareList);

    const devStmt = db.prepare('SELECT status, hostname FROM devices WHERE id = ?');
    const device = devStmt.get(deviceId);
    if (!device) return compliance;

    let targetStatus = device.status;
    if (device.status !== 'quarantined') {
      targetStatus = compliance.is_compliant ? 'online' : 'drifted';
    }

    const updateStmt = db.prepare(`
      UPDATE devices 
      SET status = ?, updated_at = DATETIME('now')
      WHERE id = ?
    `);
    updateStmt.run(targetStatus, deviceId);

    // If prohibited software detected, persist security event
    if (compliance.detected_prohibited.length > 0) {
      const eventStmt = db.prepare(`
        INSERT INTO security_events (device_id, event_type, event_source, severity, summary, raw_payload_json)
        VALUES (?, 'APP_PROHIBITED_DETECTED', 'LocalPilotPolicyEngine', 'HIGH', ?, ?)
      `);
      for (const item of compliance.detected_prohibited) {
        const summary = `Prohibited software detected on ${device.hostname}: '${item.package.name}' (${item.package.winget_id})`;
        eventStmt.run(
          deviceId,
          summary,
          JSON.stringify({
            package_id: item.package.software_id,
            winget_id: item.package.winget_id,
            installed_details: item.installed
          })
        );
      }
    }

    return compliance;
  }
};

export default policyEngine;
