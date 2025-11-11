/**
 * HPKE-Based Cryptographic Protocol (RFC 9180)
 *
 * This is a production-grade replacement for our custom ECDH+AES-GCM implementation.
 * HPKE (Hybrid Public Key Encryption) provides:
 * - Standards-compliant encryption (RFC 9180)
 * - Correct nonce management by design
 * - Integrated key derivation + AEAD
 * - Prevents common crypto mistakes
 *
 * Migration from crypto-protocol.js:
 * - Replaces: ECDH key exchange + separate AES-GCM encryption
 * - Improves: Nonce handling, key derivation, overall security
 * - Maintains: Non-extractable keys, ephemeral computation, metrics
 *
 * @see https://www.rfc-editor.org/rfc/rfc9180.html
 * @see https://github.com/dajiaji/hpke-js
 */

import {
  Aes256Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256
} from '@hpke/core';
import { X25519 } from '@hpke/dhkem-x25519';

/**
 * HPKE Configuration
 *
 * Uses the recommended cipher suite:
 * - KEM: DHKEM(X25519, HKDF-SHA256) - Elliptic curve key encapsulation
 * - KDF: HKDF-SHA256 - Key derivation function
 * - AEAD: AES-256-GCM - Authenticated encryption
 *
 * This matches the reviewer's recommendation and RFC 9180 best practices.
 */
const HPKE_SUITE = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(new X25519()),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

/**
 * @typedef {Object} HPKEKeyPair
 * @property {Uint8Array} privateKey - Private key bytes
 * @property {Uint8Array} publicKey - Public key bytes (to share with sender)
 */

/**
 * @typedef {Object} HPKEEncryptedMessage
 * @property {Uint8Array} enc - Encapsulated key (ephemeral public key)
 * @property {Uint8Array} ciphertext - Encrypted data with authentication tag
 */

/**
 * @typedef {Object} HPKEContext
 * @property {Object} sender - HPKE sender context
 * @property {Object} recipient - HPKE recipient context
 */

/**
 * Generate HPKE key pair for recipient
 *
 * This generates a static key pair for the enclave.
 * The public key is shared with the host during initialization.
 *
 * @returns {Promise<HPKEKeyPair>}
 */
export async function generateHPKEKeyPair() {
  const keyPair = await HPKE_SUITE.kem.generateKeyPair();

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey
  };
}

/**
 * Serialize public key for transmission
 *
 * Converts CryptoKey or Uint8Array to plain array for postMessage.
 *
 * @param {Uint8Array} publicKey - Public key to serialize
 * @returns {number[]} Serialized public key
 */
export function serializePublicKey(publicKey) {
  return Array.from(publicKey);
}

/**
 * Deserialize public key from transmission
 *
 * @param {number[]} serialized - Serialized public key
 * @returns {Uint8Array} Public key bytes
 */
export function deserializePublicKey(serialized) {
  return new Uint8Array(serialized);
}

/**
 * Encrypt data for recipient using HPKE
 *
 * Sender-side encryption:
 * 1. Create ephemeral sender context with recipient's public key
 * 2. Seal plaintext (encrypt + authenticate)
 * 3. Return encapsulated key (enc) + ciphertext
 *
 * The recipient uses 'enc' to derive the same shared secret.
 *
 * @param {Uint8Array} recipientPublicKey - Recipient's public key
 * @param {any} data - Data to encrypt (will be JSON stringified)
 * @param {Uint8Array} [aad] - Additional authenticated data (optional)
 * @returns {Promise<HPKEEncryptedMessage>}
 */
export async function hpkeEncrypt(recipientPublicKey, data, aad = new Uint8Array()) {
  // Encode data as JSON
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(data));

  // Create sender context (generates ephemeral key pair internally)
  const sender = await HPKE_SUITE.createSenderContext({
    recipientPublicKey: recipientPublicKey
  });

  // Seal plaintext
  // HPKE handles nonce generation internally - no manual IV management!
  const ciphertext = await sender.seal(plaintext, aad);

  return {
    enc: sender.enc,        // Encapsulated key (ephemeral public key)
    ciphertext: ciphertext  // Encrypted data with auth tag
  };
}

/**
 * Decrypt data from sender using HPKE
 *
 * Recipient-side decryption:
 * 1. Create recipient context with private key + encapsulated key (enc)
 * 2. Open ciphertext (decrypt + verify authentication)
 * 3. Return plaintext (parsed from JSON)
 *
 * @param {HPKEKeyPair} recipientKeyPair - Recipient's key pair
 * @param {HPKEEncryptedMessage} message - Encrypted message (enc + ciphertext)
 * @param {Uint8Array} [aad] - Additional authenticated data (must match encryption)
 * @returns {Promise<any>} Decrypted data (parsed from JSON)
 */
export async function hpkeDecrypt(recipientKeyPair, message, aad = new Uint8Array()) {
  try {
    // Create recipient context
    const recipient = await HPKE_SUITE.createRecipientContext({
      recipientKey: {
        privateKey: recipientKeyPair.privateKey,
        publicKey: recipientKeyPair.publicKey
      },
      enc: message.enc
    });

    // Open ciphertext (decrypt + verify)
    const plaintext = await recipient.open(message.ciphertext, aad);

    // Decode and parse JSON
    const decoder = new TextDecoder();
    const json = decoder.decode(plaintext);
    return JSON.parse(json);
  } catch (error) {
    throw new Error(`HPKE decryption failed: ${error.message}`);
  }
}

/**
 * Serialize HPKE encrypted message for postMessage
 *
 * @param {HPKEEncryptedMessage} message - Message to serialize
 * @returns {Object} Serializable object
 */
export function serializeHPKEMessage(message) {
  return {
    enc: Array.from(message.enc),
    ciphertext: Array.from(message.ciphertext)
  };
}

/**
 * Deserialize HPKE encrypted message from postMessage
 *
 * @param {Object} serialized - Serialized message
 * @returns {HPKEEncryptedMessage} Message object
 */
export function deserializeHPKEMessage(serialized) {
  return {
    enc: new Uint8Array(serialized.enc),
    ciphertext: new Uint8Array(serialized.ciphertext)
  };
}

/**
 * Generate non-extractable master key (for local encryption)
 *
 * This is still useful for encrypting data that never leaves the host origin.
 * For cross-origin communication, use HPKE instead.
 *
 * @returns {Promise<CryptoKey>}
 */
export async function generateNonExtractableKey() {
  return await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    false, // NOT extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data with AES-GCM (for local use only)
 *
 * Use HPKE for cross-origin encryption instead.
 *
 * @param {CryptoKey} key - WebCrypto key
 * @param {any} data - Data to encrypt
 * @returns {Promise<Object>}
 */
export async function encryptLocal(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(data));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    plaintext
  );

  return {
    iv: iv,
    ciphertext: new Uint8Array(ciphertext)
  };
}

/**
 * Decrypt data with AES-GCM (for local use only)
 *
 * @param {CryptoKey} key - WebCrypto key
 * @param {Object} payload - Encrypted payload
 * @returns {Promise<any>}
 */
export async function decryptLocal(key, payload) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: payload.iv },
    key,
    payload.ciphertext
  );

  const decoder = new TextDecoder();
  const json = decoder.decode(plaintext);
  return JSON.parse(json);
}

/**
 * Securely zero out a buffer
 *
 * Best-effort memory cleanup. JavaScript doesn't guarantee memory overwrite,
 * but this helps with defense-in-depth.
 *
 * @param {Uint8Array} buffer - Buffer to zero
 */
export function secureZero(buffer) {
  if (buffer && buffer.fill) {
    buffer.fill(0);
  }
}

/**
 * Measure timing of an operation
 *
 * Used for measuring key exposure windows and operation duration.
 *
 * @param {Function} operation - Async operation to measure
 * @returns {Promise<Object>} Result and timing metrics
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

/**
 * Derive code hash for attestation
 *
 * Creates SHA-256 hash of code for integrity verification.
 * Can be used in HPKE 'info' parameter for code identity binding.
 *
 * @param {string} code - Code to hash
 * @returns {Promise<Uint8Array>} SHA-256 hash
 */
export async function deriveCodeHash(code) {
  const encoder = new TextEncoder();
  const data = encoder.encode(code);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * Create HPKE context with code attestation
 *
 * Binds encryption to specific code hash for additional security.
 * Prevents ciphertext from being used with different code.
 *
 * @param {Uint8Array} recipientPublicKey - Recipient's public key
 * @param {string} code - Code being executed (for attestation)
 * @param {any} data - Data to encrypt
 * @returns {Promise<HPKEEncryptedMessage>}
 */
export async function hpkeEncryptWithAttestation(recipientPublicKey, code, data) {
  // Derive code hash
  const codeHash = await deriveCodeHash(code);

  // Use code hash as AAD (Additional Authenticated Data)
  // This binds the ciphertext to the specific code
  return await hpkeEncrypt(recipientPublicKey, data, codeHash);
}

/**
 * Decrypt HPKE message with code attestation verification
 *
 * @param {HPKEKeyPair} recipientKeyPair - Recipient's key pair
 * @param {HPKEEncryptedMessage} message - Encrypted message
 * @param {string} code - Expected code (must match encryption)
 * @returns {Promise<any>}
 */
export async function hpkeDecryptWithAttestation(recipientKeyPair, message, code) {
  const codeHash = await deriveCodeHash(code);
  return await hpkeDecrypt(recipientKeyPair, message, codeHash);
}

/**
 * Migration utilities for gradual HPKE adoption
 */

/**
 * Check if message uses HPKE format
 *
 * @param {Object} message - Message to check
 * @returns {boolean}
 */
export function isHPKEMessage(message) {
  return message && message.enc && message.ciphertext;
}

/**
 * Check if message uses legacy format (ECDH+AES-GCM)
 *
 * @param {Object} message - Message to check
 * @returns {boolean}
 */
export function isLegacyMessage(message) {
  return message && message.iv && message.ciphertext && !message.enc;
}

// Re-export timing and utility functions for compatibility
export { measureTiming as default };
