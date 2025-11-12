/**
 * Shared cryptographic protocol for secure communication
 * between host and enclave worker.
 *
 * Version 1.1 - Hardened Protocol
 * ================================
 * Changes from v1.0:
 * - Transcript binding: Session keys bound to handshake transcript (both ephemeral pubs)
 * - Sequence validation: Seq number included in encrypted body and validated
 * - Protocol versioning: All info/AAD strings include version identifier
 * - Cleaner API: seal/open instead of encryptWithSequence/decryptWithSequence
 *
 * Security properties:
 * - Non-extractable AES-GCM keys (WebCrypto enforced)
 * - Context binding (origins + code hash + transcript)
 * - Counter-based IVs (TLS 1.3 pattern, deterministic + unique)
 * - AAD on all messages (prevents message confusion)
 * - Sequence number validation (enables monotonicity checks)
 */

// ============================================================================
// Basic helpers
// ============================================================================

export const enc = (s) => new TextEncoder().encode(s);
export const dec = (b) => new TextDecoder().decode(b);
export const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

// Legacy exports for compatibility
export const encodeUtf8 = enc;
export const decodeUtf8 = dec;

/**
 * Securely zero out a Uint8Array
 * (Best effort - JS doesn't guarantee memory overwrite)
 */
export function secureZero(buffer) {
  if (buffer && buffer.fill) {
    buffer.fill(0);
  }
}

/**
 * Measure timing of an operation
 * Useful for measuring key exposure windows
 */
export async function measureTiming(operation) {
  const start = performance.now();
  const result = await operation();
  const duration = performance.now() - start;

  return {
    result,
    duration,
    durationMs: Math.round(duration * 100) / 100
  };
}

// ============================================================================
// ECDH key generation and import/export
// ============================================================================

export async function genECDH() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits", "deriveKey"]);
}

export async function exportRaw(pub) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", pub));
}

export async function importRaw(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

// Legacy exports for compatibility
export const generateECDHKeyPair = genECDH;
export const exportPublicKey = exportRaw;
export const importPublicKey = importRaw;

// ============================================================================
// Handshake transcript binding (NEW in v1.1)
// ============================================================================

/**
 * Compute order-independent hash of handshake transcript
 *
 * This binds the session key to the specific handshake instance by including
 * both ephemeral public keys. Order-independent to handle either party
 * initiating the handshake.
 *
 * @param {Uint8Array} pubA - First public key (raw bytes)
 * @param {Uint8Array} pubB - Second public key (raw bytes)
 * @returns {Promise<Uint8Array>} SHA-256 hash of transcript
 */
async function transcriptHash(pubA, pubB) {
  const a = new Uint8Array(pubA);
  const b = new Uint8Array(pubB);

  // Sort keys to make hash order-independent
  const ab = (a.length < b.length || (a.length === b.length && compare(a, b) <= 0))
    ? [a, b]
    : [b, a];

  // Concatenate sorted keys
  const cat = new Uint8Array(ab[0].length + ab[1].length);
  cat.set(ab[0], 0);
  cat.set(ab[1], ab[0].length);

  return await sha256(cat);
}

/**
 * Byte-wise comparison for sorting
 */
function compare(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const d = a[i] - b[i];
    if (d) return d;
  }
  return a.length - b.length;
}

/**
 * Concatenate multiple Uint8Arrays
 */
function concat(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ============================================================================
// Session derivation with transcript binding (NEW in v1.1)
// ============================================================================

/**
 * Derive context-bound session with transcript binding
 *
 * Version 1.1 improvements:
 * - Binds to handshake transcript (both ephemeral public keys)
 * - Versioned protocol strings in HKDF info
 * - Returns non-extractable keys
 *
 * @param {Object} opts - Derivation options
 * @param {CryptoKey} opts.privateKey - Our ECDH private key
 * @param {CryptoKey} opts.peerPublicKey - Peer's ECDH public key
 * @param {Uint8Array} opts.selfPublicKeyRaw - Our public key (raw bytes)
 * @param {Object} opts.ctx - Context for binding
 * @param {string} opts.ctx.hostOrigin - Host origin
 * @param {string} opts.ctx.enclaveOrigin - Enclave origin
 * @param {string} opts.ctx.codeHash - Code hash
 * @returns {Promise<{aeadKey: CryptoKey, baseIV: Uint8Array}>}
 *
 * @example
 * const hostKeys = await genECDH();
 * const enclaveKeys = await genECDH();
 *
 * const ctx = {
 *   hostOrigin: 'http://localhost:3000',
 *   enclaveOrigin: 'http://localhost:8081',
 *   codeHash: 'abc123...'
 * };
 *
 * const session = await deriveSession({
 *   privateKey: hostKeys.privateKey,
 *   peerPublicKey: enclaveKeys.publicKey,
 *   selfPublicKeyRaw: await exportRaw(hostKeys.publicKey),
 *   ctx
 * });
 */
export async function deriveSession(opts) {
  const { privateKey, peerPublicKey, selfPublicKeyRaw, ctx } = opts;

  // Perform ECDH to get IKM
  const ikm = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: peerPublicKey },
      privateKey,
      256
    )
  );

  // Compute transcript hash (binds to this specific handshake)
  const th = await transcriptHash(selfPublicKeyRaw, await exportRaw(peerPublicKey));

  // Create context-bound salt
  const salt = await sha256(
    enc(`${ctx.hostOrigin}|${ctx.enclaveOrigin}|${ctx.codeHash}`)
  );

  // Protocol version identifier (appears in all HKDF info strings)
  const infoBase = enc("soft-enclave/v1");

  // Import IKM as HKDF key
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    ikm,
    "HKDF",
    false,
    ["deriveKey", "deriveBits"]
  );

  // Derive AEAD key (includes transcript hash in info)
  const aeadKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: concat(infoBase, enc("/aead/"), th)
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false, // NOT extractable
    ["encrypt", "decrypt"]
  );

  // Derive base IV (includes transcript hash in info)
  const baseIV = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: concat(infoBase, enc("/iv/"), th)
      },
      hkdfKey,
      96 // 12 bytes for AES-GCM IV
    )
  );

  // Zero out IKM (best effort)
  ikm.fill(0);

  return { aeadKey, baseIV };
}

// Legacy export for compatibility (converts old API to new API)
export async function deriveSessionWithContext(privateKey, publicKey, ctx) {
  // Perform ECDH to get IKM
  const ikm = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: publicKey },
      privateKey,
      256
    )
  );

  // Create context-bound salt (same as before)
  const salt = await sha256(
    enc(`${ctx.hostOrigin||''}|${ctx.enclaveOrigin||''}|${ctx.codeHash||''}`)
  );

  // Protocol version identifier
  const infoBase = enc("soft-enclave/v1");

  // Import IKM as HKDF key
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    ikm,
    "HKDF",
    false,
    ["deriveKey", "deriveBits"]
  );

  // Derive AEAD key (without transcript hash for legacy)
  const aeadKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: concat(infoBase, enc("/aead/"))
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false, // NOT extractable
    ["encrypt", "decrypt"]
  );

  // Derive base IV (without transcript hash for legacy)
  const baseIV = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: concat(infoBase, enc("/iv/"))
      },
      hkdfKey,
      96 // 12 bytes for AES-GCM IV
    )
  );

  // Zero out IKM (best effort)
  ikm.fill(0);

  return { aeadKey, baseIV };
}

// ============================================================================
// Counter-based IV generation
// ============================================================================

/**
 * Generate IV from baseIV + sequence counter (TLS 1.3 pattern)
 *
 * Creates unique IV by XORing sequence counter into last 4 bytes of base IV.
 *
 * @param {Uint8Array} baseIV - Base IV (12 bytes)
 * @param {number} seq - Sequence number (must be > 0)
 * @returns {Uint8Array} Unique IV
 */
function ivFrom(baseIV, seq) {
  if (!Number.isInteger(seq) || seq <= 0) {
    throw new Error("invalid-seq: must be positive integer");
  }

  if (baseIV.length !== 12) {
    throw new Error("baseIV must be 12 bytes for AES-GCM");
  }

  const iv = new Uint8Array(baseIV);
  let x = seq >>> 0; // Ensure unsigned 32-bit

  // XOR sequence into last 4 bytes (big-endian)
  for (let i = 0; i < 4; i++) {
    iv[11 - i] ^= (x & 0xff);
    x >>>= 8;
  }

  return iv;
}

// Legacy export for compatibility
export const ivFromSequence = ivFrom;

// ============================================================================
// Authenticated encryption with sequence validation (NEW in v1.1)
// ============================================================================

/**
 * Seal (encrypt) message with sequence number and AAD
 *
 * Version 1.1 changes:
 * - Sequence number included in encrypted body (not just IV)
 * - Enables receiver to validate sequence monotonicity
 *
 * @param {CryptoKey} aeadKey - AES-GCM key
 * @param {Uint8Array} baseIV - Base IV from session derivation
 * @param {number} seq - Sequence number (must be > 0)
 * @param {any} body - Message body (will be JSON stringified)
 * @param {string} aad - Additional Authenticated Data (e.g., operation type)
 * @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
 */
export async function seal(aeadKey, baseIV, seq, body, aad = "") {
  const iv = ivFrom(baseIV, seq);

  // Encrypt {seq, body} together so receiver can validate sequence
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc(aad) },
    aeadKey,
    enc(JSON.stringify({ seq, body }))
  );

  return {
    iv,
    ciphertext: new Uint8Array(ct)
  };
}

/**
 * Open (decrypt) message and validate sequence number
 *
 * Version 1.1 changes:
 * - Returns {seq, body} so receiver can enforce monotonicity
 * - Validates seq is a positive integer
 *
 * @param {CryptoKey} aeadKey - AES-GCM key
 * @param {{iv: Uint8Array, ciphertext: Uint8Array}} payload - Encrypted payload
 * @param {string} aad - Additional Authenticated Data (must match seal)
 * @returns {Promise<{seq: number, body: any}>} Decrypted message with sequence
 */
export async function open(aeadKey, payload, aad = "") {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: payload.iv, additionalData: enc(aad) },
    aeadKey,
    payload.ciphertext
  );

  const msg = JSON.parse(dec(new Uint8Array(pt)));

  // Validate sequence number format
  if (!msg || !Number.isInteger(msg.seq) || msg.seq <= 0) {
    throw new Error("bad-seq: sequence number missing or invalid");
  }

  return msg; // { seq, body }
}

// Legacy exports for compatibility (wrap new API)
export async function encryptWithSequence(aeadKey, baseIV, seq, data, aadStr = '') {
  return await seal(aeadKey, baseIV, seq, data, aadStr);
}

export async function decryptWithSequence(aeadKey, payload, aadStr = '') {
  const result = await open(aeadKey, payload, aadStr);
  return result.body; // Return just body for backward compatibility
}

// ============================================================================
// Payload serialization for postMessage
// ============================================================================

export const serializePayload = (p) => ({
  iv: Array.from(p.iv),
  ciphertext: Array.from(p.ciphertext)
});

export const deserializePayload = (s) => ({
  iv: new Uint8Array(s.iv),
  ciphertext: new Uint8Array(s.ciphertext)
});

// ============================================================================
// Legacy AES-GCM helpers (kept for backward compatibility)
// ============================================================================

export async function generateNonExtractableKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function generateExtractableKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportKey(key) {
  const exported = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(exported);
}

export async function importKey(keyData) {
  return await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function encrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

export async function decrypt(key, payload) {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: payload.iv },
      key,
      payload.ciphertext
    );
    return JSON.parse(dec(new Uint8Array(plaintext)));
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

export async function deriveSharedKey(privateKey, publicKey) {
  return await crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
