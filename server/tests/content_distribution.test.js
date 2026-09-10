import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { initDb, closeDb } from '../src/db.js';
import { contentDistributionEngine } from '../src/services/contentDistributionEngine.js';

describe('Content Distribution, BITS, P2P LAN Mesh & Hardware TPM mTLS QA (Dimension 4 & 3)', () => {
  let db;
  let testDeviceId;
  let createdJobId;
  let testCertThumbprint;

  before(() => {
    db = initDb(':memory:', { seed: true });
    contentDistributionEngine._db = db;
    const dev = db.prepare('SELECT id FROM devices LIMIT 1').get();
    testDeviceId = dev.id;
  });

  after(() => {
    closeDb();
  });

  // 1. STATS
  it('DIST-01: should return baseline content distribution stats and P2P offload metrics', () => {
    const stats = contentDistributionEngine.getContentDistributionStats();
    assert.ok(stats.totalBitsJobs >= 2, 'Should have seed BITS jobs');
    assert.ok(stats.p2pActiveSeeds >= 2, 'Should have seed P2P cache seeds');
    assert.ok(typeof stats.p2pOffloadRate === 'number');
    assert.ok(stats.activeMtlsCerts >= 1, 'Should have seed mTLS cert');
    assert.ok(stats.tpmBackedCerts >= 1, 'Should have seed TPM-backed cert');
    assert.ok(stats.enrolledMtlsDevices >= 1);
  });

  // 2. LIST BITS JOBS
  it('DIST-02: should list BITS transfer jobs with device details', () => {
    const jobs = contentDistributionEngine.getBitsJobs();
    assert.ok(jobs.length >= 2);
    const win11Job = jobs.find(j => j.id === 'bits-win11-cum-01');
    assert.ok(win11Job);
    assert.strictEqual(win11Job.transfer_type, 'DOWNLOAD');
    assert.strictEqual(win11Job.priority, 'NORMAL');
    assert.strictEqual(win11Job.status, 'TRANSFERRING');
  });

  // 3. GET SINGLE BITS JOB
  it('DIST-03: should retrieve a single BITS job by ID', () => {
    const job = contentDistributionEngine.getBitsJobById('bits-edr-core-02');
    assert.ok(job);
    assert.strictEqual(job.priority, 'HIGH');
    assert.strictEqual(job.status, 'ACKNOWLEDGED');
    assert.strictEqual(job.total_bytes, 85983232);
    assert.strictEqual(job.transferred_bytes, 85983232);
  });

  // 4. CREATE BITS JOB
  it('DIST-04: should create a new BITS background download job', () => {
    const job = contentDistributionEngine.createBitsJob({
      job_name: 'Visual Studio Code Enterprise Deploy',
      device_id: testDeviceId,
      source_url: 'https://swcdn.localpilot.internal/apps/VSCodeSetup-x64.exe',
      target_local_path: 'C:\\ProgramData\\LocalPilot\\VSCodeSetup-x64.exe',
      priority: 'HIGH',
      total_bytes: 94371840,
      peer_caching_enabled: 1
    });

    assert.ok(job);
    assert.ok(job.id.startsWith('bits-'));
    assert.strictEqual(job.job_name, 'Visual Studio Code Enterprise Deploy');
    assert.strictEqual(job.status, 'QUEUED');
    assert.strictEqual(job.priority, 'HIGH');
    assert.strictEqual(job.transferred_bytes, 0);
    createdJobId = job.id;
  });

  // 5. VALIDATION ON CREATE
  it('DIST-05: should reject creating BITS job with missing mandatory fields', () => {
    assert.throws(() => {
      contentDistributionEngine.createBitsJob({
        job_name: 'Incomplete Job'
      });
    }, /required/);
  });

  // 6. UPDATE PROGRESS
  it('DIST-06: should update transferred bytes and status of BITS job', () => {
    const updated = contentDistributionEngine.updateBitsJobProgress(createdJobId, {
      transferred_bytes: 47185920,
      status: 'TRANSFERRING'
    });

    assert.ok(updated);
    assert.strictEqual(updated.transferred_bytes, 47185920);
    assert.strictEqual(updated.status, 'TRANSFERRING');
  });

  // 7. CANCEL BITS JOB
  it('DIST-07: should cancel BITS job and set status to CANCELLED', () => {
    const cancelled = contentDistributionEngine.cancelBitsJob(createdJobId);
    assert.ok(cancelled);
    assert.strictEqual(cancelled.status, 'CANCELLED');
    assert.ok(cancelled.completed_at);
  });

  // 8. GENERATE SCRIPT
  it('DIST-08: should generate native PowerShell Start-BitsTransfer script', () => {
    const job = contentDistributionEngine.getBitsJobById('bits-win11-cum-01');
    const script = contentDistributionEngine.generateBitsTransferScript(job);
    assert.ok(typeof script === 'string');
    assert.ok(script.includes('Start-BitsTransfer'));
    assert.ok(script.includes('-Priority NORMAL'));
    assert.ok(script.includes('Complete-BitsTransfer'));
    assert.ok(script.includes('LocalPilot_bits-win11-cum-01_'));
    assert.ok(script.includes('KB5034441-x64.msu'));
  });

  // 9. LIST P2P SEEDS
  it('DIST-09: should list active P2P cache seeds in subnet', () => {
    const seeds = contentDistributionEngine.getP2pSeeds();
    assert.ok(seeds.length >= 2);
    const msuSeed = seeds.find(s => s.payload_name === 'KB5034441-x64.msu');
    assert.ok(msuSeed);
    assert.strictEqual(msuSeed.is_active, 1);
    assert.strictEqual(msuSeed.p2p_port, 7680);
    assert.ok(msuSeed.bytes_served_p2p > 0);
  });

  // 10. REGISTER P2P SEED
  it('DIST-10: should register a new P2P cache chunk for LAN discovery', () => {
    const seed = contentDistributionEngine.registerP2pSeed({
      content_sha256: '99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff',
      payload_name: 'Node-v22-x64.msi',
      total_size_bytes: 35000000,
      device_id: testDeviceId,
      subnet_cidr: '192.168.1.0/24',
      lan_ip: '192.168.1.50',
      p2p_port: 7680
    });

    assert.ok(seed);
    assert.strictEqual(seed.content_sha256, '99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff');
    assert.strictEqual(seed.lan_ip, '192.168.1.50');
    assert.strictEqual(seed.bytes_served_p2p, 0);
  });

  // 11. FIND PEER SEEDS
  it('DIST-11: should discover peer cache seeds for content SHA in subnet', () => {
    const peers = contentDistributionEngine.findPeerSeedsForContent(
      '99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff',
      '192.168.1.0/24'
    );
    assert.ok(Array.isArray(peers));
    assert.strictEqual(peers.length, 1);
    assert.strictEqual(peers[0].lan_ip, '192.168.1.50');
  });

  // 12. RECORD P2P BYTES SERVED
  it('DIST-12: should increment P2P served bytes when chunks are offloaded to peers', () => {
    const seeds = contentDistributionEngine.getP2pSeeds({ content_sha256: '99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff' });
    const seedId = seeds[0].id;
    const updated = contentDistributionEngine.recordP2pBytesServed(seedId, 35000000);
    assert.strictEqual(updated.bytes_served_p2p, 35000000);
  });

  // 13. FILTER BITS JOBS BY DEVICE
  it('DIST-13: should filter BITS jobs by target device ID', () => {
    const jobs = contentDistributionEngine.getBitsJobs({ deviceId: testDeviceId });
    assert.ok(Array.isArray(jobs));
    assert.ok(jobs.length >= 1);
    jobs.forEach(j => assert.strictEqual(j.device_id, testDeviceId));
  });

  // 14. LIST MTLS CLIENT CERTIFICATES
  it('DIST-14: should list enrolled client certificates with TPM backing', () => {
    const certs = contentDistributionEngine.getMtlsCertificates();
    assert.ok(certs.length >= 1);
    const cert = certs[0];
    assert.strictEqual(cert.tpm_backed, 1);
    assert.strictEqual(cert.revocation_status, 'ACTIVE');
    assert.ok(cert.tpm_ek_pub_sha256);
  });

  // 15. ENROLL MTLS CERTIFICATE
  it('DIST-15: should enroll a new hardware TPM 2.0 backed mTLS certificate', () => {
    const enrolled = contentDistributionEngine.enrollMtlsCertificate({
      device_id: testDeviceId,
      subject_cn: 'CN=TEST-WORKSTATION-02, OU=Laptops, O=LocalPilot Fleet',
      tpm_ek_pub_sha256: '99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788',
      key_algorithm: 'RSA-2048',
      tpm_backed: 1
    });

    assert.ok(enrolled);
    assert.ok(enrolled.cert_thumbprint);
    assert.strictEqual(enrolled.revocation_status, 'ACTIVE');
    assert.strictEqual(enrolled.tpm_backed, 1);
    assert.ok(enrolled.scep_transaction_id.startsWith('SCEP-TX-'));
    testCertThumbprint = enrolled.cert_thumbprint;
  });

  // 16. VALIDATION ON ENROLL
  it('DIST-16: should reject enrollment when missing required TPM or CN fields', () => {
    assert.throws(() => {
      contentDistributionEngine.enrollMtlsCertificate({
        device_id: testDeviceId
      });
    }, /required/);
  });

  // 17. VERIFY VALID CERTIFICATE
  it('DIST-17: should verify an active, non-expired mTLS client certificate', () => {
    const result = contentDistributionEngine.verifyMtlsClientCert(testCertThumbprint);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.cert.cert_thumbprint, testCertThumbprint);
  });

  // 18. REVOKE CERTIFICATE
  it('DIST-18: should revoke an mTLS certificate with cryptographic reason', () => {
    const revoked = contentDistributionEngine.revokeMtlsCertificate(testCertThumbprint, 'KEY_COMPROMISE');
    assert.strictEqual(revoked.revocation_status, 'REVOKED');
    assert.strictEqual(revoked.revocation_reason, 'KEY_COMPROMISE');
    assert.ok(revoked.revoked_at);
  });

  // 19. VERIFY REVOKED CERTIFICATE
  it('DIST-19: should reject verification of revoked client certificate', () => {
    const result = contentDistributionEngine.verifyMtlsClientCert(testCertThumbprint);
    assert.strictEqual(result.valid, false);
    assert.ok(result.reason.includes('CERTIFICATE_REVOKED'));
  });

  // 20. VERIFY UNKNOWN CERTIFICATE
  it('DIST-20: should reject unknown certificate thumbprint', () => {
    const result = contentDistributionEngine.verifyMtlsClientCert('AABBCCDDEEFF0011223344556677889900112233');
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, 'CERTIFICATE_NOT_FOUND_IN_FLEET_PKI');
  });
});
