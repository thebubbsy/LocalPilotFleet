import crypto from 'node:crypto';
import { getDb } from '../db.js';

/**
 * LocalPilot Fleet — Content Distribution, BITS, P2P LAN Mesh & Hardware TPM mTLS Engine
 * server/src/services/contentDistributionEngine.js
 *
 * Dimension 4: Content Distribution & Bandwidth Management
 * Dimension 3: Cryptographic Identity, Zero Trust & Supply Chain Security
 */

export class ContentDistributionEngine {
  constructor(db = null) {
    this._db = db;
  }

  get db() {
    return this._db || getDb();
  }

  // ─────────────────────────────────────────────────────────────
  // 1. STATS & KPIS
  // ─────────────────────────────────────────────────────────────

  getContentDistributionStats() {
    const bitsStats = this.db.prepare(`
      SELECT
        COUNT(*) as total_jobs,
        SUM(CASE WHEN status IN ('QUEUED', 'CONNECTING', 'TRANSFERRING') THEN 1 ELSE 0 END) as active_transfers,
        SUM(CASE WHEN status IN ('TRANSFERRED', 'ACKNOWLEDGED') THEN 1 ELSE 0 END) as completed_transfers,
        SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as failed_transfers,
        COALESCE(SUM(transferred_bytes), 0) as total_transferred_bytes
      FROM bits_transfer_jobs
    `).get();

    const p2pStats = this.db.prepare(`
      SELECT
        COUNT(*) as total_seeds,
        SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_seeds,
        COALESCE(SUM(bytes_served_p2p), 0) as total_p2p_bytes_served
      FROM p2p_cache_seeds
    `).get();

    const mtlsStats = this.db.prepare(`
      SELECT
        COUNT(*) as total_certs,
        SUM(CASE WHEN revocation_status = 'ACTIVE' THEN 1 ELSE 0 END) as active_certs,
        SUM(CASE WHEN revocation_status = 'REVOKED' THEN 1 ELSE 0 END) as revoked_certs,
        SUM(CASE WHEN tpm_backed = 1 AND revocation_status = 'ACTIVE' THEN 1 ELSE 0 END) as tpm_backed_certs,
        COUNT(DISTINCT CASE WHEN revocation_status = 'ACTIVE' THEN device_id END) as enrolled_devices
      FROM device_mtls_certificates
    `).get();

    const totalBytes = Number(bitsStats.total_transferred_bytes || 0);
    const p2pBytes = Number(p2pStats.total_p2p_bytes_served || 0);
    const totalCombined = totalBytes + p2pBytes;
    const p2pOffloadRate = totalCombined > 0 ? ((p2pBytes / totalCombined) * 100).toFixed(1) : '0.0';

    return {
      totalBitsJobs: bitsStats.total_jobs || 0,
      activeBitsTransfers: bitsStats.active_transfers || 0,
      completedBitsTransfers: bitsStats.completed_transfers || 0,
      failedBitsTransfers: bitsStats.failed_transfers || 0,
      totalTransferredBytes: totalBytes,
      p2pActiveSeeds: p2pStats.active_seeds || 0,
      totalP2pBytesServed: p2pBytes,
      p2pOffloadRate: parseFloat(p2pOffloadRate),
      activeMtlsCerts: mtlsStats.active_certs || 0,
      revokedMtlsCerts: mtlsStats.revoked_certs || 0,
      tpmBackedCerts: mtlsStats.tpm_backed_certs || 0,
      enrolledMtlsDevices: mtlsStats.enrolled_devices || 0
    };
  }

  // ─────────────────────────────────────────────────────────────
  // 2. BITS BACKGROUND INTELLIGENT TRANSFER SERVICE
  // ─────────────────────────────────────────────────────────────

  getBitsJobs(filters = {}) {
    let query = `
      SELECT b.*, d.friendly_name as device_name, d.hostname as device_hostname
      FROM bits_transfer_jobs b
      LEFT JOIN devices d ON b.device_id = d.id
      WHERE 1=1
    `;
    const params = [];

    if (filters.deviceId) {
      query += ' AND b.device_id = ?';
      params.push(filters.deviceId);
    }
    if (filters.status) {
      query += ' AND b.status = ?';
      params.push(filters.status);
    }
    if (filters.priority) {
      query += ' AND b.priority = ?';
      params.push(filters.priority);
    }

    query += ' ORDER BY b.created_at DESC';
    return this.db.prepare(query).all(...params);
  }

  getBitsJobById(id) {
    return this.db.prepare(`
      SELECT b.*, d.friendly_name as device_name, d.hostname as device_hostname
      FROM bits_transfer_jobs b
      LEFT JOIN devices d ON b.device_id = d.id
      WHERE b.id = ?
    `).get(id) || null;
  }

  createBitsJob(jobData) {
    if (!jobData.job_name || !jobData.device_id || !jobData.source_url || !jobData.target_local_path) {
      throw new Error('job_name, device_id, source_url, and target_local_path are required');
    }

    const id = jobData.id || `bits-${crypto.randomBytes(6).toString('hex')}`;
    const transferType = jobData.transfer_type || 'DOWNLOAD';
    const priority = jobData.priority || 'NORMAL';
    const peerCaching = jobData.peer_caching_enabled !== undefined ? (jobData.peer_caching_enabled ? 1 : 0) : 1;
    const totalBytes = Number(jobData.total_bytes || 0);

    this.db.prepare(`
      INSERT INTO bits_transfer_jobs (
        id, job_name, device_id, source_url, target_local_path, transfer_type, priority, total_bytes, transferred_bytes, status, peer_caching_enabled
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'QUEUED', ?)
    `).run(
      id,
      jobData.job_name,
      jobData.device_id,
      jobData.source_url,
      jobData.target_local_path,
      transferType,
      priority,
      totalBytes,
      peerCaching
    );

    return this.getBitsJobById(id);
  }

  updateBitsJobProgress(id, updateData) {
    const job = this.getBitsJobById(id);
    if (!job) {
      throw new Error(`BITS job not found: ${id}`);
    }

    const transferred = updateData.transferred_bytes !== undefined ? Number(updateData.transferred_bytes) : job.transferred_bytes;
    const total = updateData.total_bytes !== undefined ? Number(updateData.total_bytes) : job.total_bytes;
    const status = updateData.status || job.status;
    const errorCode = updateData.error_code !== undefined ? updateData.error_code : job.error_code;
    const completedAt = ['TRANSFERRED', 'ACKNOWLEDGED', 'CANCELLED', 'ERROR'].includes(status) 
      ? (job.completed_at || new Date().toISOString()) 
      : null;

    this.db.prepare(`
      UPDATE bits_transfer_jobs
      SET transferred_bytes = ?, total_bytes = ?, status = ?, error_code = ?, completed_at = ?
      WHERE id = ?
    `).run(transferred, total, status, errorCode, completedAt, id);

    return this.getBitsJobById(id);
  }

  cancelBitsJob(id) {
    const job = this.getBitsJobById(id);
    if (!job) {
      throw new Error(`BITS job not found: ${id}`);
    }

    this.db.prepare(`
      UPDATE bits_transfer_jobs
      SET status = 'CANCELLED', completed_at = DATETIME('now')
      WHERE id = ?
    `).run(id);

    return this.getBitsJobById(id);
  }

  generateBitsTransferScript(job) {
    if (!job) return '';

    return `# LocalPilot Fleet — Native BITS Background Intelligent Transfer Script
# Job ID: ${job.id} | Priority: ${job.priority} | Peer Caching: ${job.peer_caching_enabled ? 'Enabled' : 'Disabled'}
[CmdletBinding()]
param(
    [string]$FleetServerUrl = "https://localhost:8443",
    [string]$FleetKey = "YOUR-FLEET-KEY"
)

$ErrorActionPreference = 'Stop'
$JobDisplayName = "LocalPilot_${job.id}_$([System.IO.Path]::GetFileName('${job.target_local_path}'))"

Write-Host "[-] Initializing BITS ${job.transfer_type} for ${job.job_name}..." -ForegroundColor Cyan

# Ensure target folder exists
$targetDir = Split-Path -Path "${job.target_local_path}" -Parent
if ($targetDir -and -not (Test-Path -Path $targetDir)) {
    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
}

try {
    # Check if job already exists in BITS queue
    $existingJob = Get-BitsTransfer -Name $JobDisplayName -ErrorAction SilentlyContinue
    if (-not $existingJob) {
        Write-Host "[-] Registering new BITS transfer job with priority ${job.priority}..."
        $bitsJob = Start-BitsTransfer -Source "${job.source_url}" \`
                                      -Destination "${job.target_local_path}" \`
                                      -DisplayName $JobDisplayName \`
                                      -Priority ${job.priority} \`
                                      -Asynchronous
    } else {
        $bitsJob = $existingJob
        Write-Host "[-] Resuming existing BITS job state: $($bitsJob.JobState)..."
    }

    # Monitor progress loop
    while ($bitsJob.JobState -in @('Queued', 'Connecting', 'Transferring')) {
        Start-Sleep -Seconds 3
        $bitsJob = Get-BitsTransfer -Name $JobDisplayName -ErrorAction SilentlyContinue
        if (-not $bitsJob) { break }
        
        $percent = 0
        if ($bitsJob.BytesTotal -gt 0) {
            $percent = [math]::Round(($bitsJob.BytesTransferred / $bitsJob.BytesTotal) * 100, 1)
        }
        Write-Host "[-] BITS Progress: $percent% ($($bitsJob.BytesTransferred) / $($bitsJob.BytesTotal) bytes)"
    }

    if ($bitsJob.JobState -eq 'Transferred') {
        Complete-BitsTransfer -BitsJob $bitsJob
        Write-Host "[+] BITS transfer successfully completed and committed: ${job.target_local_path}" -ForegroundColor Green
    }
} catch {
    Write-Error "[-] BITS Transfer failed: $_"
    exit 1
}
`;
  }

  // ─────────────────────────────────────────────────────────────
  // 3. P2P LAN MESH & SUBNET CACHE
  // ─────────────────────────────────────────────────────────────

  getP2pSeeds(filters = {}) {
    let query = `
      SELECT p.*, d.friendly_name as device_name, d.hostname as device_hostname
      FROM p2p_cache_seeds p
      LEFT JOIN devices d ON p.device_id = d.id
      WHERE 1=1
    `;
    const params = [];

    if (filters.content_sha256) {
      query += ' AND p.content_sha256 = ?';
      params.push(filters.content_sha256);
    }
    if (filters.subnet_cidr) {
      query += ' AND p.subnet_cidr = ?';
      params.push(filters.subnet_cidr);
    }
    if (filters.is_active !== undefined) {
      query += ' AND p.is_active = ?';
      params.push(filters.is_active ? 1 : 0);
    }

    query += ' ORDER BY p.bytes_served_p2p DESC, p.created_at DESC';
    return this.db.prepare(query).all(...params);
  }

  registerP2pSeed(seedData) {
    if (!seedData.content_sha256 || !seedData.payload_name || !seedData.device_id || !seedData.lan_ip) {
      throw new Error('content_sha256, payload_name, device_id, and lan_ip are required');
    }

    const existing = this.db.prepare(`
      SELECT id FROM p2p_cache_seeds
      WHERE content_sha256 = ? AND device_id = ?
    `).get(seedData.content_sha256, seedData.device_id);

    const subnet = seedData.subnet_cidr || '192.168.1.0/24';
    const port = Number(seedData.p2p_port || 7680);
    const size = Number(seedData.total_size_bytes || 0);

    if (existing) {
      this.db.prepare(`
        UPDATE p2p_cache_seeds
        SET lan_ip = ?, p2p_port = ?, is_active = 1, subnet_cidr = ?, total_size_bytes = ?
        WHERE id = ?
      `).run(seedData.lan_ip, port, subnet, size, existing.id);
      return this.db.prepare('SELECT * FROM p2p_cache_seeds WHERE id = ?').get(existing.id);
    } else {
      const id = seedData.id || `p2p-${crypto.randomBytes(6).toString('hex')}`;
      this.db.prepare(`
        INSERT INTO p2p_cache_seeds (
          id, content_sha256, payload_name, total_size_bytes, device_id, subnet_cidr, lan_ip, p2p_port, bytes_served_p2p, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1)
      `).run(id, seedData.content_sha256, seedData.payload_name, size, seedData.device_id, subnet, seedData.lan_ip, port);
      return this.db.prepare('SELECT * FROM p2p_cache_seeds WHERE id = ?').get(id);
    }
  }

  findPeerSeedsForContent(contentSha256, subnetCidr) {
    let query = `
      SELECT p.*, d.friendly_name as device_name, d.hostname as device_hostname
      FROM p2p_cache_seeds p
      LEFT JOIN devices d ON p.device_id = d.id
      WHERE p.content_sha256 = ? AND p.is_active = 1
    `;
    const params = [contentSha256];

    if (subnetCidr) {
      query += ' AND p.subnet_cidr = ?';
      params.push(subnetCidr);
    }

    query += ' ORDER BY p.bytes_served_p2p ASC';
    return this.db.prepare(query).all(...params);
  }

  recordP2pBytesServed(id, bytesServed) {
    this.db.prepare(`
      UPDATE p2p_cache_seeds
      SET bytes_served_p2p = bytes_served_p2p + ?
      WHERE id = ?
    `).run(Number(bytesServed || 0), id);

    return this.db.prepare('SELECT * FROM p2p_cache_seeds WHERE id = ?').get(id);
  }

  // ─────────────────────────────────────────────────────────────
  // 4. TPM 2.0 & CLIENT MTLS ENROLLMENT
  // ─────────────────────────────────────────────────────────────

  getMtlsCertificates(filters = {}) {
    let query = `
      SELECT c.*, d.friendly_name as device_name, d.hostname as device_hostname
      FROM device_mtls_certificates c
      LEFT JOIN devices d ON c.device_id = d.id
      WHERE 1=1
    `;
    const params = [];

    if (filters.deviceId) {
      query += ' AND c.device_id = ?';
      params.push(filters.deviceId);
    }
    if (filters.revocation_status) {
      query += ' AND c.revocation_status = ?';
      params.push(filters.revocation_status);
    }
    if (filters.tpm_backed !== undefined) {
      query += ' AND c.tpm_backed = ?';
      params.push(filters.tpm_backed ? 1 : 0);
    }

    query += ' ORDER BY c.created_at DESC';
    return this.db.prepare(query).all(...params);
  }

  getMtlsCertByThumbprint(thumbprint) {
    const normThumb = thumbprint.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
    return this.db.prepare(`
      SELECT c.*, d.friendly_name as device_name, d.hostname as device_hostname
      FROM device_mtls_certificates c
      LEFT JOIN devices d ON c.device_id = d.id
      WHERE UPPER(c.cert_thumbprint) = ?
    `).get(normThumb) || null;
  }

  enrollMtlsCertificate(enrollData) {
    if (!enrollData.device_id || !enrollData.subject_cn || !enrollData.tpm_ek_pub_sha256) {
      throw new Error('device_id, subject_cn, and tpm_ek_pub_sha256 are required for mTLS enrollment');
    }

    const id = enrollData.id || `mtls-${crypto.randomBytes(6).toString('hex')}`;
    const thumbprint = enrollData.cert_thumbprint 
      ? enrollData.cert_thumbprint.replace(/[^A-Fa-f0-9]/g, '').toUpperCase()
      : crypto.createHash('sha1').update(`${enrollData.device_id}-${enrollData.subject_cn}-${Date.now()}`).digest('hex').toUpperCase();

    const issuerCn = enrollData.issuer_cn || 'LocalPilot Root Enterprise Device CA';
    const tpmBacked = enrollData.tpm_backed !== undefined ? (enrollData.tpm_backed ? 1 : 0) : 1;
    const keyAlgorithm = enrollData.key_algorithm || 'RSA-2048';
    const scepTxId = enrollData.scep_transaction_id || `SCEP-TX-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    const validFrom = enrollData.valid_from || new Date().toISOString();
    const validToDate = new Date();
    validToDate.setFullYear(validToDate.getFullYear() + 2);
    const validTo = enrollData.valid_to || validToDate.toISOString();

    this.db.prepare(`
      INSERT INTO device_mtls_certificates (
        id, device_id, cert_thumbprint, subject_cn, issuer_cn, tpm_backed, tpm_ek_pub_sha256, key_algorithm, scep_transaction_id, valid_from, valid_to, revocation_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
    `).run(
      id,
      enrollData.device_id,
      thumbprint,
      enrollData.subject_cn,
      issuerCn,
      tpmBacked,
      enrollData.tpm_ek_pub_sha256,
      keyAlgorithm,
      scepTxId,
      validFrom,
      validTo
    );

    return this.getMtlsCertByThumbprint(thumbprint);
  }

  revokeMtlsCertificate(idOrThumbprint, reason = 'SUPERSEDED') {
    const norm = idOrThumbprint.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
    const cert = this.db.prepare(`
      SELECT * FROM device_mtls_certificates
      WHERE id = ? OR UPPER(cert_thumbprint) = ?
    `).get(idOrThumbprint, norm);

    if (!cert) {
      throw new Error(`Certificate not found: ${idOrThumbprint}`);
    }

    this.db.prepare(`
      UPDATE device_mtls_certificates
      SET revocation_status = 'REVOKED', revoked_at = DATETIME('now'), revocation_reason = ?
      WHERE id = ?
    `).run(reason, cert.id);

    return this.db.prepare('SELECT * FROM device_mtls_certificates WHERE id = ?').get(cert.id);
  }

  verifyMtlsClientCert(thumbprint) {
    if (!thumbprint) {
      return { valid: false, reason: 'NO_CERTIFICATE_THUMBPRINT_PROVIDED' };
    }

    const cert = this.getMtlsCertByThumbprint(thumbprint);
    if (!cert) {
      return { valid: false, reason: 'CERTIFICATE_NOT_FOUND_IN_FLEET_PKI' };
    }

    if (cert.revocation_status === 'REVOKED') {
      return { valid: false, reason: `CERTIFICATE_REVOKED: ${cert.revocation_reason}`, cert };
    }

    const now = new Date();
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);

    if (now < validFrom) {
      return { valid: false, reason: 'CERTIFICATE_NOT_YET_VALID', cert };
    }

    if (now > validTo) {
      return { valid: false, reason: 'CERTIFICATE_EXPIRED', cert };
    }

    return { valid: true, cert };
  }
}

export const contentDistributionEngine = new ContentDistributionEngine();
export default contentDistributionEngine;
