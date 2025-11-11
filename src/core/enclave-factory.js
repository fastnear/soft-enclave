/**
 * Enclave Factory - Unified Entry Point
 *
 * Provides a simple factory API for creating enclaves with different
 * isolation mechanisms and protocol configurations.
 *
 * Usage:
 *
 * ```javascript
 * // Worker-based with advanced protocol (default)
 * const enclave = createEnclave();
 *
 * // iframe-based with simple protocol
 * const enclave = createEnclave({ mode: 'iframe', protocol: 'simple' });
 *
 * // Worker-based with HPKE protocol
 * const enclave = createEnclave({ mode: 'worker', protocol: 'hpke' });
 * ```
 */

import { WorkerBackend } from '../backends/worker-backend.js';
import { IframeBackend } from '../backends/iframe-backend.js';

/**
 * Available backend modes
 */
export const EnclaveMode = {
  WORKER: 'worker',
  IFRAME: 'iframe'
};

/**
 * Available protocol types
 */
export const ProtocolType = {
  SIMPLE: 'simple',    // Basic ECDH+HKDF (near-outlayer)
  ADVANCED: 'advanced', // Advanced with transcript binding (default)
  HPKE: 'hpke'        // HPKE for post-quantum readiness
};

/**
 * Security tier recommendations based on transaction value
 */
export const SecurityTier = {
  // Tier 1: Convenience-first (< $100 transactions)
  CONVENIENCE: {
    mode: EnclaveMode.WORKER,
    protocol: ProtocolType.SIMPLE,
    description: 'In-page QuickJS sandbox with basic encryption'
  },

  // Tier 2: Enhanced security ($100-$10K transactions)
  ENHANCED: {
    mode: EnclaveMode.IFRAME,
    protocol: ProtocolType.ADVANCED,
    description: 'Cross-origin iframe with advanced protocol'
  },

  // Tier 3: Maximum browser security ($10K+ transactions)
  MAXIMUM: {
    mode: EnclaveMode.WORKER,
    protocol: ProtocolType.HPKE,
    description: 'Cross-origin worker with HPKE protocol'
  }

  // Tier 4 (not implemented): Hardware TEE with attestation
  // For $100K+ treasury operations, use hardware wallet or TEE backend
};

/**
 * Recommend security tier based on transaction value
 *
 * @param {number} valueUSD - Transaction value in USD
 * @returns {object} Recommended security tier configuration
 */
export function recommendTier(valueUSD) {
  if (valueUSD < 100) {
    return SecurityTier.CONVENIENCE;
  } else if (valueUSD < 10000) {
    return SecurityTier.ENHANCED;
  } else {
    return SecurityTier.MAXIMUM;
  }
}

/**
 * Create an enclave instance
 *
 * @param {object} options - Configuration options
 * @param {string} options.mode - Backend mode ('worker' or 'iframe')
 * @param {string} options.protocol - Protocol type ('simple', 'advanced', 'hpke')
 * @param {string} options.workerUrl - Custom worker URL (worker mode only)
 * @param {string} options.enclaveOrigin - Custom enclave origin (iframe mode only)
 * @param {number} options.timeout - Request timeout in ms (default: 30000)
 * @returns {EnclaveBase} Enclave instance
 *
 * @example
 * // Default: worker mode with advanced protocol
 * const enclave = createEnclave();
 * await enclave.initialize();
 * const result = await enclave.execute('40 + 2');
 *
 * @example
 * // iframe mode with simple protocol
 * const enclave = createEnclave({ mode: 'iframe', protocol: 'simple' });
 * await enclave.initialize();
 * const result = await enclave.execute('fibonacci(10)');
 *
 * @example
 * // Security tier based on transaction value
 * const tier = recommendTier(5000); // Returns ENHANCED tier
 * const enclave = createEnclave(tier);
 */
export function createEnclave(options = {}) {
  const {
    mode = EnclaveMode.WORKER,
    protocol = ProtocolType.ADVANCED,
    ...backendOptions
  } = options;

  // Validate mode
  if (!Object.values(EnclaveMode).includes(mode)) {
    throw new Error(`Invalid mode: ${mode}. Must be one of: ${Object.values(EnclaveMode).join(', ')}`);
  }

  // Validate protocol
  if (!Object.values(ProtocolType).includes(protocol)) {
    throw new Error(`Invalid protocol: ${protocol}. Must be one of: ${Object.values(ProtocolType).join(', ')}`);
  }

  // Create backend instance
  const config = {
    protocol,
    ...backendOptions
  };

  switch (mode) {
    case EnclaveMode.WORKER:
      return new WorkerBackend(config);

    case EnclaveMode.IFRAME:
      return new IframeBackend(config);

    default:
      throw new Error(`Unsupported mode: ${mode}`);
  }
}

/**
 * Legacy compatibility: export HybridSecureEnclave as alias for WorkerBackend
 *
 * This maintains backward compatibility with existing code that uses
 * the HybridSecureEnclave class directly.
 */
export { WorkerBackend as HybridSecureEnclave };

/**
 * Convenience exports
 */
export { EnclaveBase } from './enclave-base.js';
export { WorkerBackend } from '../backends/worker-backend.js';
export { IframeBackend } from '../backends/iframe-backend.js';
