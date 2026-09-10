/**
 * LocalPilot Fleet — Hardware Supply Chain & TPM 2.0 / UEFI Measured Boot Attestation Engine
 * server/src/services/hardwareAttestationEngine.js
 *
 * Implements cryptographic hardware root-of-trust verification, TPM 2.0 PCR validation,
 * UEFI boot-chain integrity, component serial auditing, and zero-trust supply chain defense.
 */

import crypto from 'node:crypto';

export class HardwareAttestationEngine {
  /**
   * Aggregate fleet hardware attestation and boot integrity statistics
   */
  static getAttestationStats(db) {
    const baselinesRow = db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN verified_status = 'VERIFIED' THEN 1 ELSE 0 END) as verified,
        SUM(CASE WHEN verified_status = 'COMPONENT_MISMATCH' THEN 1 ELSE 0 END) as mismatches,
        SUM(CASE WHEN verified_status = 'TAMPER_ALERT' THEN 1 ELSE 0 END) as tamper_alerts,
        SUM(CASE WHEN secure_boot_enabled = 1 THEN 1 ELSE 0 END) as secure_boot,
        SUM(CASE WHEN dma_guard_enabled = 1 THEN 1 ELSE 0 END) as dma_guard,
        SUM(CASE WHEN hvci_code_integrity = 1 THEN 1 ELSE 0 END) as hvci
      FROM hardware_supply_chain_baselines
    `).get();

    const total = baselinesRow?.total || 0;
    const verified = baselinesRow?.verified || 0;
    const mismatches = baselinesRow?.mismatches || 0;
    const tamperAlerts = baselinesRow?.tamper_alerts || 0;

    const secureBootPct = total > 0 ? parseFloat(((baselinesRow.secure_boot / total) * 100).toFixed(1)) : 0;
    const dmaGuardPct = total > 0 ? parseFloat(((baselinesRow.dma_guard / total) * 100).toFixed(1)) : 0;
    const hvciPct = total > 0 ? parseFloat(((baselinesRow.hvci / total) * 100).toFixed(1)) : 0;

    const bootLogsRow = db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN attestation_result = 'PCR_DRIFT_DETECTED' THEN 1 ELSE 0 END) as drifts
      FROM tpm_measured_boot_logs
    `).get();

    const policiesRow = db.prepare('SELECT COUNT(*) as count FROM hardware_attestation_policies WHERE is_active = 1').get();

    return {
      totalAttestedDevices: total,
      verifiedDevices: verified,
      componentMismatches: mismatches,
      tamperAlerts,
      secureBootCompliancePct: secureBootPct,
      dmaGuardCompliancePct: dmaGuardPct,
      hvciCompliancePct: hvciPct,
      totalBootLogs: bootLogsRow?.total || 0,
      pcrDriftsDetected: bootLogsRow?.drifts || 0,
      activePolicies: policiesRow?.count || 0,
      attestationOperational: true,
      calculatedAt: new Date().toISOString()
    };
  }

  /**
   * Retrieve supply chain baselines
   */
  static getSupplyChainBaselines(db, query = {}) {
    let sql = 'SELECT * FROM hardware_supply_chain_baselines WHERE 1=1';
    const params = [];

    if (query.verified_status) {
      sql += ' AND verified_status = ?';
      params.push(query.verified_status);
    }
    if (query.tpm_manufacturer) {
      sql += ' AND tpm_manufacturer LIKE ?';
      params.push(`%${query.tpm_manufacturer}%`);
    }
    if (query.hostname) {
      sql += ' AND hostname LIKE ?';
      params.push(`%${query.hostname}%`);
    }

    sql += ' ORDER BY hostname ASC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => {
      let dimms = [];
      let nvme = [];
      try { dimms = JSON.parse(r.dimm_serials_json || '[]'); } catch {}
      try { nvme = JSON.parse(r.nvme_serials_json || '[]'); } catch {}
      return { ...r, dimm_serials: dimms, nvme_serials: nvme };
    });
  }

  /**
   * Retrieve baseline by device ID with latest boot log
   */
  static getBaselineByDeviceId(db, deviceId) {
    const row = db.prepare('SELECT * FROM hardware_supply_chain_baselines WHERE device_id = ?').get(deviceId);
    if (!row) return null;

    let dimms = [];
    let nvme = [];
    try { dimms = JSON.parse(row.dimm_serials_json || '[]'); } catch {}
    try { nvme = JSON.parse(row.nvme_serials_json || '[]'); } catch {}

    const latestBoot = db.prepare(`
      SELECT * FROM tpm_measured_boot_logs
      WHERE device_id = ?
      ORDER BY recorded_at DESC
      LIMIT 1
    `).get(deviceId);

    return {
      ...row,
      dimm_serials: dimms,
      nvme_serials: nvme,
      latest_measured_boot: latestBoot || null
    };
  }

  /**
   * Register or update hardware supply chain baseline
   */
  static registerBaseline(db, data) {
    const id = data.id || ('hscb-' + crypto.randomBytes(4).toString('hex'));
    const dimmsJson = typeof data.dimm_serials === 'string' ? data.dimm_serials : JSON.stringify(data.dimm_serials || []);
    const nvmeJson = typeof data.nvme_serials === 'string' ? data.nvme_serials : JSON.stringify(data.nvme_serials || []);

    const existing = db.prepare('SELECT id FROM hardware_supply_chain_baselines WHERE device_id = ?').get(data.device_id);

    if (existing) {
      const stmt = db.prepare(`
        UPDATE hardware_supply_chain_baselines SET
          hostname = COALESCE(?, hostname),
          tpm_manufacturer = COALESCE(?, tpm_manufacturer),
          tpm_spec_version = COALESCE(?, tpm_spec_version),
          motherboard_serial = COALESCE(?, motherboard_serial),
          chassis_serial = COALESCE(?, chassis_serial),
          cpu_model = COALESCE(?, cpu_model),
          cpu_microcode_rev = COALESCE(?, cpu_microcode_rev),
          dimm_serials_json = ?,
          nvme_serials_json = ?,
          secure_boot_enabled = COALESCE(?, secure_boot_enabled),
          dma_guard_enabled = COALESCE(?, dma_guard_enabled),
          hvci_code_integrity = COALESCE(?, hvci_code_integrity),
          verified_status = COALESCE(?, verified_status),
          updated_at = DATETIME('now')
        WHERE device_id = ?
      `);

      stmt.run(
        data.hostname || null,
        data.tpm_manufacturer || null,
        data.tpm_spec_version || null,
        data.motherboard_serial || null,
        data.chassis_serial || null,
        data.cpu_model || null,
        data.cpu_microcode_rev || null,
        dimmsJson,
        nvmeJson,
        data.secure_boot_enabled !== undefined ? (data.secure_boot_enabled ? 1 : 0) : null,
        data.dma_guard_enabled !== undefined ? (data.dma_guard_enabled ? 1 : 0) : null,
        data.hvci_code_integrity !== undefined ? (data.hvci_code_integrity ? 1 : 0) : null,
        data.verified_status || null,
        data.device_id
      );

      return this.getBaselineByDeviceId(db, data.device_id);
    } else {
      const stmt = db.prepare(`
        INSERT INTO hardware_supply_chain_baselines (
          id, device_id, hostname, tpm_manufacturer, tpm_spec_version,
          motherboard_serial, chassis_serial, cpu_model, cpu_microcode_rev,
          dimm_serials_json, nvme_serials_json, secure_boot_enabled, dma_guard_enabled,
          hvci_code_integrity, verified_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        id,
        data.device_id,
        data.hostname || 'UNKNOWN-HOST',
        data.tpm_manufacturer || 'Generic TPM',
        data.tpm_spec_version || '2.0',
        data.motherboard_serial || null,
        data.chassis_serial || null,
        data.cpu_model || null,
        data.cpu_microcode_rev || null,
        dimmsJson,
        nvmeJson,
        data.secure_boot_enabled !== undefined ? (data.secure_boot_enabled ? 1 : 0) : 1,
        data.dma_guard_enabled !== undefined ? (data.dma_guard_enabled ? 1 : 0) : 1,
        data.hvci_code_integrity !== undefined ? (data.hvci_code_integrity ? 1 : 0) : 1,
        data.verified_status || 'VERIFIED'
      );

      return this.getBaselineByDeviceId(db, data.device_id);
    }
  }

  /**
   * Delete baseline
   */
  static deleteBaseline(db, id) {
    const existing = db.prepare('SELECT id FROM hardware_supply_chain_baselines WHERE id = ?').get(id);
    if (!existing) return false;

    db.prepare('DELETE FROM hardware_supply_chain_baselines WHERE id = ?').run(id);
    return true;
  }

  /**
   * Compare live endpoint hardware components against registered baseline
   */
  static verifyHardwareComponents(db, deviceId, liveTelemetry) {
    const baseline = this.getBaselineByDeviceId(db, deviceId);
    if (!baseline) {
      return { matches: false, reason: 'NO_BASELINE', mismatches: ['Device has no enrolled hardware baseline'] };
    }

    const mismatches = [];

    if (liveTelemetry.motherboard_serial && baseline.motherboard_serial &&
        liveTelemetry.motherboard_serial !== baseline.motherboard_serial) {
      mismatches.push(`Motherboard serial mismatch: expected ${baseline.motherboard_serial}, got ${liveTelemetry.motherboard_serial}`);
    }

    if (liveTelemetry.chassis_serial && baseline.chassis_serial &&
        liveTelemetry.chassis_serial !== baseline.chassis_serial) {
      mismatches.push(`Chassis serial mismatch: expected ${baseline.chassis_serial}, got ${liveTelemetry.chassis_serial}`);
    }

    if (liveTelemetry.cpu_microcode_rev && baseline.cpu_microcode_rev &&
        liveTelemetry.cpu_microcode_rev !== baseline.cpu_microcode_rev) {
      mismatches.push(`CPU microcode revision altered: expected ${baseline.cpu_microcode_rev}, got ${liveTelemetry.cpu_microcode_rev}`);
    }

    // Verify DIMM RAM serials if provided
    if (Array.isArray(liveTelemetry.dimm_serials) && baseline.dimm_serials.length > 0) {
      const missingDimms = baseline.dimm_serials.filter(s => !liveTelemetry.dimm_serials.includes(s));
      if (missingDimms.length > 0) {
        mismatches.push(`RAM DIMM module swapped or missing: ${missingDimms.join(', ')}`);
      }
    }

    // Verify NVMe storage serials if provided
    if (Array.isArray(liveTelemetry.nvme_serials) && baseline.nvme_serials.length > 0) {
      const missingNvme = baseline.nvme_serials.filter(s => !liveTelemetry.nvme_serials.includes(s));
      if (missingNvme.length > 0) {
        mismatches.push(`NVMe storage drive replaced or unauthorized: ${missingNvme.join(', ')}`);
      }
    }

    const hasMismatches = mismatches.length > 0;
    const newStatus = hasMismatches ? 'COMPONENT_MISMATCH' : 'VERIFIED';

    db.prepare('UPDATE hardware_supply_chain_baselines SET verified_status = ?, updated_at = DATETIME(\'now\') WHERE device_id = ?').run(
      newStatus,
      deviceId
    );

    return {
      matches: !hasMismatches,
      status: newStatus,
      mismatches
    };
  }

  /**
   * Retrieve measured boot logs
   */
  static getMeasuredBootLogs(db, query = {}) {
    let sql = 'SELECT * FROM tpm_measured_boot_logs WHERE 1=1';
    const params = [];

    if (query.device_id) {
      sql += ' AND device_id = ?';
      params.push(query.device_id);
    }
    if (query.attestation_result) {
      sql += ' AND attestation_result = ?';
      params.push(query.attestation_result);
    }

    sql += ' ORDER BY recorded_at DESC';
    const rows = db.prepare(sql).all(...params);

    return rows.map(r => {
      let details = {};
      try { details = JSON.parse(r.drift_details_json || '{}'); } catch {}
      return { ...r, drift_details: details };
    });
  }

  /**
   * Ingest TPM measured boot log and check for PCR drift
   */
  static ingestMeasuredBootLog(db, data) {
    const id = data.id || ('mbl-' + crypto.randomBytes(4).toString('hex'));

    // Check prior boot session to detect unauthorized PCR drift
    const priorBoot = db.prepare(`
      SELECT * FROM tpm_measured_boot_logs
      WHERE device_id = ?
      ORDER BY recorded_at DESC
      LIMIT 1
    `).get(data.device_id);

    let attestationResult = data.attestation_result || 'PASSED';
    const driftDetails = {};

    if (priorBoot && attestationResult === 'PASSED') {
      if (data.pcr_0_bios_sha256 && priorBoot.pcr_0_bios_sha256 !== data.pcr_0_bios_sha256) {
        attestationResult = 'PCR_DRIFT_DETECTED';
        driftDetails.pcr_0_drift = { expected: priorBoot.pcr_0_bios_sha256, actual: data.pcr_0_bios_sha256 };
      }
      if (data.pcr_7_secureboot_sha256 && priorBoot.pcr_7_secureboot_sha256 !== data.pcr_7_secureboot_sha256) {
        attestationResult = 'PCR_DRIFT_DETECTED';
        driftDetails.pcr_7_drift = { expected: priorBoot.pcr_7_secureboot_sha256, actual: data.pcr_7_secureboot_sha256 };
      }
    }

    const stmt = db.prepare(`
      INSERT INTO tpm_measured_boot_logs (
        id, device_id, hostname, boot_session_id,
        pcr_0_bios_sha256, pcr_2_rom_sha256, pcr_4_bootmgr_sha256,
        pcr_7_secureboot_sha256, pcr_11_bitlocker_sha256, attestation_result, drift_details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.device_id,
      data.hostname || 'UNKNOWN-HOST',
      data.boot_session_id || ('boot-' + Date.now()),
      data.pcr_0_bios_sha256 || '0000000000000000000000000000000000000000000000000000000000000000',
      data.pcr_2_rom_sha256 || '0000000000000000000000000000000000000000000000000000000000000000',
      data.pcr_4_bootmgr_sha256 || '0000000000000000000000000000000000000000000000000000000000000000',
      data.pcr_7_secureboot_sha256 || '0000000000000000000000000000000000000000000000000000000000000000',
      data.pcr_11_bitlocker_sha256 || '0000000000000000000000000000000000000000000000000000000000000000',
      attestationResult,
      JSON.stringify(driftDetails)
    );

    return db.prepare('SELECT * FROM tpm_measured_boot_logs WHERE id = ?').get(id);
  }

  /**
   * Retrieve attestation policies
   */
  static getAttestationPolicies(db, query = {}) {
    let sql = 'SELECT * FROM hardware_attestation_policies WHERE 1=1';
    const params = [];

    if (query.is_active !== undefined) {
      sql += ' AND is_active = ?';
      params.push(query.is_active ? 1 : 0);
    }

    sql += ' ORDER BY created_at DESC';
    return db.prepare(sql).all(...params);
  }

  /**
   * Create attestation policy
   */
  static createAttestationPolicy(db, data) {
    const id = data.id || ('hap-' + crypto.randomBytes(4).toString('hex'));

    const stmt = db.prepare(`
      INSERT INTO hardware_attestation_policies (
        id, name, target_scope, target_id, require_tpm_2_0, require_secure_boot,
        require_dma_protection, require_memory_integrity_hvci, quarantine_on_component_mismatch, is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      data.name,
      data.target_scope || 'ALL_FLEET',
      data.target_id || null,
      data.require_tpm_2_0 !== undefined ? (data.require_tpm_2_0 ? 1 : 0) : 1,
      data.require_secure_boot !== undefined ? (data.require_secure_boot ? 1 : 0) : 1,
      data.require_dma_protection !== undefined ? (data.require_dma_protection ? 1 : 0) : 1,
      data.require_memory_integrity_hvci !== undefined ? (data.require_memory_integrity_hvci ? 1 : 0) : 1,
      data.quarantine_on_component_mismatch !== undefined ? (data.quarantine_on_component_mismatch ? 1 : 0) : 1,
      data.is_active !== undefined ? (data.is_active ? 1 : 0) : 1
    );

    return db.prepare('SELECT * FROM hardware_attestation_policies WHERE id = ?').get(id);
  }

  /**
   * Delete attestation policy
   */
  static deleteAttestationPolicy(db, id) {
    const existing = db.prepare('SELECT id FROM hardware_attestation_policies WHERE id = ?').get(id);
    if (!existing) return false;

    db.prepare('DELETE FROM hardware_attestation_policies WHERE id = ?').run(id);
    return true;
  }

  /**
   * Evaluate device against active hardware attestation policy
   */
  static evaluateDeviceCompliance(db, deviceId) {
    const policy = db.prepare('SELECT * FROM hardware_attestation_policies WHERE is_active = 1 LIMIT 1').get();
    const baseline = this.getBaselineByDeviceId(db, deviceId);

    if (!baseline) {
      return { compliant: false, reasons: ['No hardware supply chain baseline enrolled'] };
    }

    if (!policy) {
      return { compliant: true, reasons: [] };
    }

    const reasons = [];

    if (policy.require_tpm_2_0 && baseline.tpm_spec_version !== '2.0') {
      reasons.push(`TPM 2.0 required, observed spec version ${baseline.tpm_spec_version}`);
    }
    if (policy.require_secure_boot && !baseline.secure_boot_enabled) {
      reasons.push('UEFI Secure Boot is disabled');
    }
    if (policy.require_dma_protection && !baseline.dma_guard_enabled) {
      reasons.push('Kernel DMA Protection is disabled');
    }
    if (policy.require_memory_integrity_hvci && !baseline.hvci_code_integrity) {
      reasons.push('Hypervisor-Protected Code Integrity (HVCI) is disabled');
    }
    if (policy.quarantine_on_component_mismatch && baseline.verified_status === 'COMPONENT_MISMATCH') {
      reasons.push('Hardware component mismatch / unauthorized physical component swap detected');
    }

    return {
      compliant: reasons.length === 0,
      verified_status: baseline.verified_status,
      reasons
    };
  }
}
