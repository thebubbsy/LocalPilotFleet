/**
 * LocalPilot Fleet — Enterprise PKI Code-Signing Authority & Digital Payload Verification Engine
 * server/src/services/pkiSigningEngine.js
 *
 * Dimension 3: Cryptographic Identity, Zero Trust & Tamper Resistance
 * Provides enterprise-grade asymmetric key generation (RSA-2048 / RSA-4096),
 * digital payload signing (SHA256-RSA), tamper-proof signature envelopes for PowerShell/remediations,
 * cryptographic verification, key rotation, and public CA certificate distribution for agents.
 */

import crypto from 'node:crypto';

export function getPkiStats(db) {
  const totalKeys = db.prepare('SELECT COUNT(*) as c FROM enterprise_signing_keys').get().c;
  const activeKeys = db.prepare('SELECT COUNT(*) as c FROM enterprise_signing_keys WHERE is_active = 1 AND is_revoked = 0').get().c;
  const revokedKeys = db.prepare('SELECT COUNT(*) as c FROM enterprise_signing_keys WHERE is_revoked = 1').get().c;
  const totalManifests = db.prepare('SELECT COUNT(*) as c FROM signed_payload_manifests').get().c;

  const typeCounts = db.prepare(`
    SELECT payload_type, COUNT(*) as count
    FROM signed_payload_manifests
    GROUP BY payload_type
  `).all();

  const activeKey = db.prepare(`
    SELECT id, name, key_type, thumbprint, expires_at, created_at
    FROM enterprise_signing_keys
    WHERE is_active = 1 AND is_revoked = 0
    ORDER BY created_at DESC
    LIMIT 1
  `).get() || null;

  return {
    total_keys: totalKeys,
    active_keys: activeKeys,
    revoked_keys: revokedKeys,
    total_signed_manifests: totalManifests,
    payloads_by_type: typeCounts.reduce((acc, row) => {
      acc[row.payload_type] = row.count;
      return acc;
    }, {}),
    active_authority: activeKey,
    status: activeKey ? 'OPERATIONAL' : 'NO_ACTIVE_AUTHORITY'
  };
}

export function getSigningKeys(db, includeRevoked = true) {
  let sql = `
    SELECT id, name, key_type, public_key_pem, thumbprint, is_active, is_revoked,
           revocation_reason, expires_at, created_at,
           (SELECT COUNT(*) FROM signed_payload_manifests WHERE key_id = enterprise_signing_keys.id) as signed_count
    FROM enterprise_signing_keys
  `;
  if (!includeRevoked) {
    sql += ' WHERE is_revoked = 0';
  }
  sql += ' ORDER BY is_active DESC, created_at DESC';
  return db.prepare(sql).all();
}

export function getSigningKeyById(db, id, includePrivate = false) {
  const cols = includePrivate
    ? '*'
    : 'id, name, key_type, public_key_pem, thumbprint, is_active, is_revoked, revocation_reason, expires_at, created_at';
  return db.prepare(`SELECT ${cols} FROM enterprise_signing_keys WHERE id = ?`).get(id) || null;
}

export function getActiveSigningKey(db, includePrivate = false) {
  const cols = includePrivate
    ? '*'
    : 'id, name, key_type, public_key_pem, thumbprint, is_active, is_revoked, revocation_reason, expires_at, created_at';
  return db.prepare(`
    SELECT ${cols}
    FROM enterprise_signing_keys
    WHERE is_active = 1 AND is_revoked = 0
    ORDER BY created_at DESC
    LIMIT 1
  `).get() || null;
}

export function getPublicCertificate(db) {
  const activeKey = getActiveSigningKey(db, false);
  if (!activeKey) {
    return { error: 'No active code-signing authority configured', code: 'NO_ACTIVE_KEY' };
  }
  return {
    key_id: activeKey.id,
    name: activeKey.name,
    key_type: activeKey.key_type,
    thumbprint: activeKey.thumbprint,
    expires_at: activeKey.expires_at,
    public_key_pem: activeKey.public_key_pem,
    algorithm: 'SHA256withRSA'
  };
}

export function generateSigningKey(db, {
  name = 'Enterprise Root Code-Signing Authority',
  keyType = 'RSA-2048',
  validityYears = 5,
  setAsActive = true
} = {}) {
  const modulusLength = keyType === 'RSA-4096' ? 4096 : 2048;

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const thumbprint = crypto.createHash('sha256').update(publicKey).digest('hex').toUpperCase();
  const id = `pki-key-${crypto.randomBytes(6).toString('hex')}`;

  if (setAsActive) {
    db.prepare('UPDATE enterprise_signing_keys SET is_active = 0 WHERE is_active = 1').run();
  }

  const expiresAtModifier = `+${parseInt(validityYears, 10) || 5} years`;

  db.prepare(`
    INSERT INTO enterprise_signing_keys (
      id, name, key_type, public_key_pem, private_key_pem, thumbprint, is_active, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, DATETIME('now', ?))
  `).run(
    id,
    name,
    keyType,
    publicKey,
    privateKey,
    thumbprint,
    setAsActive ? 1 : 0,
    expiresAtModifier
  );

  return getSigningKeyById(db, id, false);
}

export function rotateSigningKey(db, options = {}) {
  const previousActive = getActiveSigningKey(db, false);
  const newKeyName = options.name || `Rotated Code-Signing Key (${new Date().toISOString().split('T')[0]})`;
  const newKey = generateSigningKey(db, {
    name: newKeyName,
    keyType: options.keyType || 'RSA-2048',
    validityYears: options.validityYears || 3,
    setAsActive: true
  });

  return {
    previous_key: previousActive,
    active_key: newKey,
    rotated_at: new Date().toISOString()
  };
}

export function revokeSigningKey(db, id, reason = 'Administrative revocation') {
  const key = getSigningKeyById(db, id, false);
  if (!key) return null;

  db.prepare(`
    UPDATE enterprise_signing_keys
    SET is_revoked = 1, is_active = 0, revocation_reason = ?
    WHERE id = ?
  `).run(reason, id);

  return getSigningKeyById(db, id, false);
}

export function signPayload(db, {
  payload,
  payloadType = 'SCRIPT',
  targetId = null,
  keyId = null
}) {
  if (typeof payload !== 'string') {
    throw new Error('Payload must be a string');
  }

  let signingKey;
  if (keyId) {
    signingKey = getSigningKeyById(db, keyId, true);
  } else {
    signingKey = getActiveSigningKey(db, true);
  }

  if (!signingKey) {
    throw new Error('No valid signing key found');
  }
  if (signingKey.is_revoked) {
    throw new Error('Signing key has been revoked');
  }

  // Compute SHA-256 hash of payload
  const sha256Hash = crypto.createHash('sha256').update(payload, 'utf8').digest('hex');

  // Sign with RSA-SHA256
  const signer = crypto.createSign('SHA256');
  signer.update(payload, 'utf8');
  signer.end();
  const signatureBase64 = signer.sign(signingKey.private_key_pem, 'base64');

  const manifestId = `sig-${crypto.randomBytes(8).toString('hex')}`;

  db.prepare(`
    INSERT INTO signed_payload_manifests (
      id, key_id, payload_type, target_id, sha256_hash, signature_base64, signer_thumbprint
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    manifestId,
    signingKey.id,
    payloadType,
    targetId || null,
    sha256Hash,
    signatureBase64,
    signingKey.thumbprint
  );

  const envelope = buildSignatureEnvelope({
    keyId: signingKey.id,
    thumbprint: signingKey.thumbprint,
    sha256: sha256Hash,
    signature: signatureBase64
  });

  return {
    manifest_id: manifestId,
    key_id: signingKey.id,
    signer_thumbprint: signingKey.thumbprint,
    sha256_hash: sha256Hash,
    signature_base64: signatureBase64,
    signed_at: new Date().toISOString(),
    envelope
  };
}

export function buildSignatureEnvelope({ keyId, thumbprint, sha256, signature }) {
  return [
    '# SIG # BEGIN LOCALPILOT ENTERPRISE SIGNATURE',
    `# Key-Id: ${keyId}`,
    `# Thumbprint: ${thumbprint}`,
    `# SHA256: ${sha256}`,
    `# Signature: ${signature}`,
    '# SIG # END LOCALPILOT ENTERPRISE SIGNATURE'
  ].join('\r\n');
}

export function wrapScriptWithSignature(db, scriptContent, { payloadType = 'SCRIPT', targetId = null } = {}) {
  const signResult = signPayload(db, {
    payload: scriptContent,
    payloadType,
    targetId
  });

  const wrappedScript = `${scriptContent.trimEnd()}\r\n\r\n${signResult.envelope}\r\n`;

  return {
    ...signResult,
    wrapped_script: wrappedScript
  };
}

export function verifyPayload(db, {
  payload,
  signatureBase64,
  signerThumbprint = null,
  keyId = null
}) {
  if (typeof payload !== 'string' || typeof signatureBase64 !== 'string') {
    return { valid: false, error: 'Invalid payload or signature argument' };
  }

  let key = null;
  if (signerThumbprint) {
    key = db.prepare('SELECT * FROM enterprise_signing_keys WHERE thumbprint = ?').get(signerThumbprint);
  } else if (keyId) {
    key = db.prepare('SELECT * FROM enterprise_signing_keys WHERE id = ?').get(keyId);
  } else {
    key = getActiveSigningKey(db, false);
  }

  if (!key) {
    return { valid: false, error: 'Signing key or thumbprint not recognized in trust store' };
  }

  if (key.is_revoked) {
    return {
      valid: false,
      key_id: key.id,
      thumbprint: key.thumbprint,
      is_revoked: true,
      error: `Key ${key.id} is revoked: ${key.revocation_reason || 'Unknown reason'}`
    };
  }

  try {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(payload, 'utf8');
    verifier.end();
    const isValid = verifier.verify(key.public_key_pem, signatureBase64, 'base64');

    return {
      valid: isValid,
      key_id: key.id,
      key_name: key.name,
      thumbprint: key.thumbprint,
      is_revoked: false,
      error: isValid ? null : 'Signature verification failed (content modified or invalid signature)'
    };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

export function extractAndVerifyScriptEnvelope(db, scriptText) {
  if (!scriptText || typeof scriptText !== 'string') {
    return { valid: false, error: 'Empty script payload' };
  }

  const sigBlockRegex = /# SIG # BEGIN LOCALPILOT ENTERPRISE SIGNATURE\r?\n# Key-Id: ([^\r\n]+)\r?\n# Thumbprint: ([^\r\n]+)\r?\n# SHA256: ([^\r\n]+)\r?\n# Signature: ([^\r\n]+)\r?\n# SIG # END LOCALPILOT ENTERPRISE SIGNATURE/m;
  const match = scriptText.match(sigBlockRegex);

  if (!match) {
    return {
      valid: false,
      error: 'Missing LocalPilot enterprise digital signature envelope'
    };
  }

  const [fullMatch, keyId, thumbprint, sha256, signatureBase64] = match;
  const contentWithoutSig = scriptText.replace(fullMatch, '').trimEnd();

  const verification = verifyPayload(db, {
    payload: contentWithoutSig,
    signatureBase64,
    signerThumbprint: thumbprint,
    keyId
  });

  return {
    ...verification,
    extracted_hash: sha256,
    extracted_thumbprint: thumbprint,
    extracted_key_id: keyId,
    clean_payload: contentWithoutSig
  };
}

export function getSigningManifests(db, { payloadType = null, limit = 50 } = {}) {
  let sql = `
    SELECT m.*, k.name as key_name, k.key_type
    FROM signed_payload_manifests m
    JOIN enterprise_signing_keys k ON m.key_id = k.id
  `;
  const params = [];

  if (payloadType) {
    sql += ' WHERE m.payload_type = ?';
    params.push(payloadType);
  }

  sql += ' ORDER BY m.signed_at DESC LIMIT ?';
  params.push(parseInt(limit, 10) || 50);

  return db.prepare(sql).all(...params);
}
