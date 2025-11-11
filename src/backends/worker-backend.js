/**
 * Worker Backend - Cross-Origin Worker Isolation
 *
 * Implements secure enclave using Web Workers with cross-origin isolation.
 *
 * Security layers:
 * 1. WebCrypto non-extractable keys (primary defense)
 * 2. Cross-origin worker isolation (SOP barrier)
 * 3. QuickJS-WASM sandboxing (execution isolation)
 * 4. Ephemeral computation (limited exposure window)
 *
 * This backend uses the advanced crypto protocol (v1.1) with:
 * - Context-bound ECDH key exchange
 * - Transcript binding
 * - Sequence number discipline
 * - AAD for message authentication
 */

import { EnclaveBase } from '../core/enclave-base.js';

import {
  generateNonExtractableKey,
  generateECDHKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveSharedKey,
  encrypt,
  decrypt,
  serializePayload,
  deserializePayload,
  sha256,
  encodeUtf8,
  deriveSessionWithContext,
  encryptWithSequence,
  decryptWithSequence,
  seal,  // v1.1 API
  open   // v1.1 API
} from '../shared/crypto-protocol.js';

import {
  MessageType,
  AAD,
  createMessage,
  generateMessageId
} from '../shared/message-types.js';

/**
 * Worker-based secure enclave backend
 */
export class WorkerBackend extends EnclaveBase {
  static MODE = 'worker';

  constructor(options = {}) {
    super(options);

    this.workerUrl = options.workerUrl || this._detectWorkerUrl();
    this.worker = null;
    this.masterKey = null; // Non-extractable WebCrypto key
    this.sessionKey = null; // Derived session key (AEAD key from HKDF)
    this.baseIV = null; // Base IV for counter-based IV generation
    this.codeHash = null; // Hash of enclave code for attestation
    this.pendingRequests = new Map();

    // Sequence number discipline (v1.1)
    // ====================================
    // Counters start at 0. First message uses seq=1 (via ++sendSeq).
    // Ensures sequence numbers are always positive integers per protocol.
    this.sendSeq = 0;
  }

  /**
   * Auto-detect worker URL based on environment
   * @private
   */
  _detectWorkerUrl() {
    // In development, assume worker is on different port
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
      const workerPort = parseInt(location.port) + 1;
      return `http://${location.hostname}:${workerPort}/enclave-worker.js`;
    }

    // In production, use different subdomain
    return `https://enclave.${location.hostname}/enclave-worker.js`;
  }

  /**
   * Validate worker-specific options
   * @protected
   */
  _validateOptions(options) {
    const baseOptions = super._validateOptions(options);
    return {
      ...baseOptions,
      workerUrl: options.workerUrl || null
    };
  }

  /**
   * Perform worker initialization
   * @protected
   */
  async _performInitialization() {
    // Layer 1: Generate non-extractable master key
    console.log('[WorkerBackend] Generating non-extractable master key...');
    this.masterKey = await generateNonExtractableKey();

    // Layer 2: Initialize cross-origin worker
    console.log(`[WorkerBackend] Loading worker from: ${this.workerUrl}`);
    this.worker = new Worker(this.workerUrl, { type: 'module' });

    // Set up message handler
    this.worker.addEventListener('message', this._handleWorkerMessage.bind(this));
    this.worker.addEventListener('error', this._handleWorkerError.bind(this));

    // Perform ECDH key exchange with worker
    await this._performKeyExchange();
  }

  /**
   * Perform ECDH key exchange with context binding
   * @private
   */
  async _performKeyExchange() {
    console.log('[WorkerBackend] Starting context-bound ECDH key exchange...');

    // Compute code hash from worker URL (attestation)
    const workerUrlBytes = encodeUtf8(this.workerUrl);
    this.codeHash = await sha256(workerUrlBytes);
    const codeHashHex = Array.from(this.codeHash)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    console.log(`[WorkerBackend] Code hash: ${codeHashHex.substring(0, 16)}...`);

    // Generate ephemeral ECDH key pair
    const keyPair = await generateECDHKeyPair();
    const publicKeyData = await exportPublicKey(keyPair.publicKey);

    // Send public key + code hash to worker
    const response = await this._sendMessageAndWait({
      type: MessageType.KEY_EXCHANGE,
      publicKey: Array.from(publicKeyData),
      codeHash: Array.from(this.codeHash)
    });

    // Import worker's public key
    const workerPublicKey = await importPublicKey(
      new Uint8Array(response.publicKey)
    );

    // Derive context-bound session key + baseIV with transcript binding
    const ctx = {
      hostOrigin: window.location.origin,
      enclaveOrigin: new URL(this.workerUrl).origin,
      codeHash: codeHashHex
    };

    const session = await deriveSessionWithContext({
      privateKey: keyPair.privateKey,
      peerPublicKey: workerPublicKey,
      selfPublicKeyRaw: publicKeyData, // Transcript binding (v1.1)
      ctx
    });

    this.sessionKey = session.aeadKey;
    this.baseIV = session.baseIV;

    console.log('[WorkerBackend] Context-bound session established');
    console.log(`[WorkerBackend] Context: ${JSON.stringify(ctx)}`);
  }

  /**
   * Perform code execution in worker
   * @protected
   */
  async _performExecution(code, context, options) {
    // Encrypt context with all protocol requirements
    const { payload, seq } = await this._secureSeal(context, AAD.EXECUTE);

    // Send to worker
    const response = await this._sendMessageAndWait({
      type: MessageType.EXECUTE,
      code: code,
      encryptedContext: payload,
      seq: seq
    });

    // Decrypt result with AAD
    const { body: result } = await open(
      this.sessionKey,
      deserializePayload(response.encryptedResult),
      AAD.EXECUTE_RESULT
    );

    return {
      result,
      metrics: response.metrics
    };
  }

  /**
   * Perform cleanup
   * @protected
   */
  async _performCleanup() {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.pendingRequests.clear();
  }

  /**
   * Securely seal (encrypt) data for transmission to enclave
   *
   * This helper encapsulates the encryption flow:
   * 1. Increment sequence counter (pre-increment ensures seq >= 1)
   * 2. Encrypt with seal() using AAD
   * 3. Serialize for postMessage
   *
   * @param {any} data - Data to encrypt
   * @param {string} aad - Additional Authenticated Data (e.g., AAD.EXECUTE)
   * @returns {Promise<{payload: Object, seq: number}>} Serialized payload and sequence number
   * @private
   */
  async _secureSeal(data, aad) {
    const seq = ++this.sendSeq;
    const encrypted = await seal(
      this.sessionKey,
      this.baseIV,
      seq,
      data,
      aad
    );
    return {
      payload: serializePayload(encrypted),
      seq
    };
  }

  /**
   * Sign a transaction with an encrypted private key
   *
   * This is a backend-specific method (not in base interface)
   */
  async signTransaction(encryptedKey, transaction) {
    this._ensureInitialized();

    console.log('[WorkerBackend] Signing transaction in enclave...');

    // Encrypt key and transaction with separate sequences
    const key = await this._secureSeal(
      { encryptedKey: Array.from(encryptedKey) },
      AAD.SIGN_TRANSACTION_KEY
    );
    const tx = await this._secureSeal(
      transaction,
      AAD.SIGN_TRANSACTION_TX
    );

    const startTime = performance.now();

    const response = await this._sendMessageAndWait({
      type: MessageType.SIGN_TRANSACTION,
      encryptedKey: key.payload,
      encryptedTransaction: tx.payload,
      keySeq: key.seq,
      txSeq: tx.seq
    });

    const totalDuration = performance.now() - startTime;

    // Decrypt signature with AAD
    const { body: signature } = await open(
      this.sessionKey,
      deserializePayload(response.encryptedSignature),
      AAD.SIGN_RESULT
    );

    // Update metrics
    this._updateMetrics(response.metrics);

    console.log(`[WorkerBackend] Signing complete in ${totalDuration.toFixed(2)}ms`);
    console.log(`[WorkerBackend] Key exposure window: ${response.metrics.keyExposureMs.toFixed(2)}ms`);

    return {
      signature,
      metrics: response.metrics,
      totalDurationMs: totalDuration
    };
  }

  /**
   * Send message to worker and wait for response
   * @private
   */
  _sendMessageAndWait(payload, timeout = 30000) {
    return new Promise((resolve, reject) => {
      const id = generateMessageId();

      // Store pending request
      const timeoutId = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Request timeout after ${timeout}ms`));
      }, timeout);

      this.pendingRequests.set(id, {
        resolve: (response) => {
          clearTimeout(timeoutId);
          this.pendingRequests.delete(id);
          resolve(response);
        },
        reject: (error) => {
          clearTimeout(timeoutId);
          this.pendingRequests.delete(id);
          reject(error);
        }
      });

      // Send message
      this.worker.postMessage({
        id,
        ...payload
      });
    });
  }

  /**
   * Handle messages from worker
   * @private
   */
  _handleWorkerMessage(event) {
    const message = event.data;

    // Find pending request
    const pending = this.pendingRequests.get(message.id);
    if (!pending) {
      console.warn('[WorkerBackend] Received message for unknown request:', message.id);
      return;
    }

    // Handle response
    if (message.error) {
      pending.reject(new Error(message.error));
    } else {
      pending.resolve(message);
    }
  }

  /**
   * Handle worker errors
   * @private
   */
  _handleWorkerError(event) {
    console.error('[WorkerBackend] Worker error:', event);

    // Reject all pending requests
    for (const [id, pending] of this.pendingRequests) {
      pending.reject(new Error('Worker error'));
    }
    this.pendingRequests.clear();
  }
}
