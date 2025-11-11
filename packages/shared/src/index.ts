// Soft Enclave Shared - Main entry point

// Main crypto protocol (includes common utilities: generateNonExtractableKey, measureTiming, secureZero)
export * from './crypto-protocol.js'

// HPKE protocol (excludes duplicate utilities)
export {
  generateHPKEKeyPair,
  serializePublicKey,
  deserializePublicKey,
  hpkeEncrypt,
  hpkeDecrypt,
  serializeHPKEMessage,
  deserializeHPKEMessage,
  encryptLocal,
  decryptLocal,
  deriveCodeHash,
  hpkeEncryptWithAttestation,
  hpkeDecryptWithAttestation,
  isHPKEMessage,
  isLegacyMessage
} from './crypto-protocol-hpke.js'

export * from './deterministic-shims.js'
export * from './message-types.js'

// Persistence (Phase 3)
export * from './keystore.js'
export * from './storage.js'
