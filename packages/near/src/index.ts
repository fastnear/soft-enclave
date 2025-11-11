// NEAR Integration - Main entry point

// Legacy NEAR integration (from near-outlayer)
export * from './storage-shim.js'
export * from './deterministic-prelude.js'

// New NEAR adapter (view-only RPC integration)
export * from './host/rpc.js'
export * from './enclave/near-enclave.js'

// Transaction signing (Phase 2)
export * from './enclave/base58.js'
export * from './enclave/near-tx.js'
