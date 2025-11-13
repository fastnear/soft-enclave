/**
 * iframe Backend - Cross-Origin iframe Isolation
 *
 * Implements secure enclave using cross-origin iframes with MessageChannel.
 * This is the architecture from near-outlayer's soft enclave.
 *
 * Security layers:
 * 1. Cross-origin iframe isolation (SOP barrier)
 * 2. MessageChannel communication (no direct access)
 * 3. Egress guard (ciphertext-only enforcement)
 * 4. QuickJS-WASM sandboxing (execution isolation)
 *
 * This backend uses the simple crypto protocol:
 * - Basic ECDH + HKDF key exchange
 * - Counter-based IVs
 * - AAD for message authentication
 * - IV replay protection in enclave
 */

import { EnclaveBase } from '@fastnear/soft-enclave-core';

/**
 * iframe-based secure enclave backend
 *
 * This wraps the near-outlayer EnclaveClient and adapts it to
 * our unified EnclaveBase interface.
 *
 * Note: The actual EnclaveClient implementation will be provided
 * by importing from src/backends/iframe/host/enclave-client.js
 * which is ported from near-outlayer.
 */
export class IframeBackend extends EnclaveBase {
  static MODE = 'iframe';

  enclaveOrigin: string;
  client: any;
  codeHashOverride: string | null;

  constructor(options: any = {}) {
    super(options);

    this.enclaveOrigin = options.enclaveOrigin || this._detectEnclaveOrigin();
    this.client = null; // Will be EnclaveClient instance
    this.codeHashOverride = options.codeHashOverride || null;
  }

  /**
   * Auto-detect enclave origin based on environment
   * @private
   */
  _detectEnclaveOrigin() {
    // In development, assume enclave is on different port
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
      const enclavePort = parseInt(location.port) + 10; // Different from worker (+1)
      return `http://${location.hostname}:${enclavePort}`;
    }

    // In production, use different subdomain
    return `https://enclave.${location.hostname}`;
  }

  /**
   * Validate iframe-specific options
   * @protected
   */
  _validateOptions(options) {
    const baseOptions = super._validateOptions(options);
    return {
      ...baseOptions,
      enclaveOrigin: options.enclaveOrigin || null,
      codeHashOverride: options.codeHashOverride || null
    };
  }

  /**
   * Perform iframe initialization
   * @protected
   */
  async _performInitialization() {
    // Lazy load EnclaveClient (will be ported in Phase 2)
    const { EnclaveClient } = await import('./host/enclave-client.js');

    console.log(`[IframeBackend] Creating iframe at: ${this.enclaveOrigin}`);
    this.client = new EnclaveClient(this.enclaveOrigin);

    // Boot the enclave (ECDH handshake + iframe creation)
    await this.client.boot({ codeHashOverride: this.codeHashOverride });

    console.log('[IframeBackend] iframe enclave booted successfully');
  }

  /**
   * Perform code execution in iframe
   * @protected
   */
  async _performExecution(code, context, options) {
    const startTime = performance.now();

    // Send 'evalQuickJS' operation to enclave
    // EnclaveClient.send() returns the decrypted result directly
    const result = await this.client.send('evalQuickJS', {
      code,
      context: JSON.stringify(context)
    }, 'op=evalQuickJS');

    const keyExposureMs = performance.now() - startTime;

    // Return enclave's actual metrics (keyExposureMs from inside enclave)
    // Use enclave's measurement if available, otherwise use round-trip time
    return {
      result: result.body,
      metrics: {
        keyExposureMs: result.keyExposureMs || keyExposureMs,
        logs: result.logs || [],
        memoryZeroed: result.memoryZeroed !== undefined ? result.memoryZeroed : true
      }
    };
  }

  /**
   * Perform cleanup
   * @protected
   */
  async _performCleanup() {
    if (this.client && this.client.iframe) {
      // Remove iframe from DOM
      this.client.iframe.remove();
      this.client = null;
    }
  }

  /**
   * Sign transaction operation (iframe-specific)
   *
   * This adapts the execute pattern to transaction signing
   */
  async signTransaction(encryptedKey, transaction) {
    this._ensureInitialized();

    console.log('[IframeBackend] Signing transaction in enclave...');
    const startTime = performance.now();

    const result = await this.client.send('signTransaction', {
      encryptedKey: Array.from(encryptedKey),
      transaction
    }, 'op=signTransaction');

    const totalDuration = performance.now() - startTime;
    const metrics = {
      keyExposureMs: result.keyExposureMs || totalDuration,
      memoryZeroed: result.memoryZeroed !== undefined ? result.memoryZeroed : true
    };

    this._updateMetrics(metrics);

    console.log(`[IframeBackend] Signing complete in ${totalDuration.toFixed(2)}ms`);

    return {
      signature: {
        type: result.body.type || 'ed25519',
        data: result.body.data || [],
        signature: result.body.signature
      },
      signedTransaction: result.body.signedTransaction,
      metrics,
      totalDurationMs: totalDuration
    };
  }

  /**
   * Get last sent payload (for testing)
   *
   * Exposes the raw encrypted payload for replay testing
   */
  getLastPayload() {
    if (!this.client) {
      throw new Error('Client not initialized');
    }
    return this.client.lastPayload();
  }

  /**
   * Resend raw payload (for testing)
   *
   * Allows replay attacks for security testing
   */
  resendRaw(serialized) {
    if (!this.client) {
      throw new Error('Client not initialized');
    }
    return this.client.resendRaw(serialized);
  }
}
