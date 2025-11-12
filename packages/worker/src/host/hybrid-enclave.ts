/**
 * Hybrid Secure Enclave - Host Side
 *
 * Defense-in-depth approach:
 * 1. WebCrypto non-extractable keys (primary defense)
 * 2. Cross-origin worker isolation (SOP barrier)
 * 3. QuickJS-WASM sandboxing (execution isolation)
 * 4. Ephemeral computation (limited exposure window)
 */

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
  deriveSession,
  encryptWithSequence,
  decryptWithSequence,
  seal,  // v1.1 API
  open   // v1.1 API
} from '@fastnear/soft-enclave-shared';

import {
  MessageType,
  AAD,
  createMessage,
  generateMessageId
} from '@fastnear/soft-enclave-shared';

/**
 * Hybrid secure enclave client
 */
export class HybridSecureEnclave {
  workerUrl: string;
  worker: Worker | null;
  masterKey: CryptoKey | null;
  sessionKey: CryptoKey | null;
  baseIV: Uint8Array | null;
  codeHash: Uint8Array | null;
  pendingRequests: Map<string, any>;
  initialized: boolean;
  sendSeq: number;
  metrics: any;

  constructor(workerUrl: string | null = null) {
    this.workerUrl = workerUrl || this.detectWorkerUrl();
    this.worker = null;
    this.masterKey = null; // Non-extractable WebCrypto key
    this.sessionKey = null; // Derived session key (AEAD key from HKDF)
    this.baseIV = null; // Base IV for counter-based IV generation
    this.codeHash = null; // Hash of enclave code for attestation
    this.pendingRequests = new Map();
    this.initialized = false;

    // Sequence number discipline (v1.1)
    // ====================================
    // Counters start at 0. First message uses seq=1 (via ++sendSeq).
    // Ensures sequence numbers are always positive integers per protocol.
    this.sendSeq = 0;
    this.metrics = {
      operationsCount: 0,
      averageKeyExposureMs: 0,
      totalKeyExposureMsSum: 0
    };
  }

  /**
   * Auto-detect worker URL based on environment
   */
  detectWorkerUrl() {
    // In development, assume worker is on different port
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
      const workerPort = parseInt(location.port) + 1;
      return `http://${location.hostname}:${workerPort}/enclave-worker.js`;
    }

    // In production, use different subdomain
    return `https://enclave.${location.hostname}/enclave-worker.js`;
  }

  /**
   * Initialize the secure enclave
   */
  async initialize() {
    console.log('[HybridEnclave] Initializing...');

    // Layer 1: Generate non-extractable master key
    console.log('[HybridEnclave] Generating non-extractable master key...');
    this.masterKey = await generateNonExtractableKey();

    // Layer 2: Initialize cross-origin worker
    console.log(`[HybridEnclave] Loading worker from: ${this.workerUrl}`);
    this.worker = new Worker(this.workerUrl, { type: 'module' });

    // Set up message handler
    this.worker.addEventListener('message', this.handleWorkerMessage.bind(this));
    this.worker.addEventListener('error', this.handleWorkerError.bind(this));

    // Perform ECDH key exchange with worker
    await this.performKeyExchange();

    this.initialized = true;
    console.log('[HybridEnclave] Initialization complete');
  }

  /**
   * Perform ECDH key exchange with context binding
   */
  async performKeyExchange() {
    console.log('[HybridEnclave] Starting context-bound ECDH key exchange...');

    // Compute code hash from worker URL (attestation)
    const workerUrlBytes = encodeUtf8(this.workerUrl);
    this.codeHash = await sha256(workerUrlBytes);
    const codeHashHex = Array.from(this.codeHash)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    console.log(`[HybridEnclave] Code hash: ${codeHashHex.substring(0, 16)}...`);

    // Generate ephemeral ECDH key pair
    const keyPair = await generateECDHKeyPair();
    const publicKeyData = await exportPublicKey(keyPair.publicKey);

    // Send public key + code hash to worker
    const response: any = await this.sendMessageAndWait({
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
      hostOrigin: globalThis.location.origin,
      enclaveOrigin: new URL(this.workerUrl).origin,
      codeHash: codeHashHex
    };

    const session = await deriveSession({
      privateKey: keyPair.privateKey,
      peerPublicKey: workerPublicKey,
      selfPublicKeyRaw: publicKeyData, // Transcript binding (v1.1)
      ctx
    });

    this.sessionKey = session.aeadKey;
    this.baseIV = session.baseIV;

    console.log('[HybridEnclave] Context-bound session established');
    console.log(`[HybridEnclave] Context: ${JSON.stringify(ctx)}`);
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
   */
  async secureSeal(data, aad) {
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
   * Execute code in the secure enclave
   */
  async execute(code, context = {}) {
    this.ensureInitialized();

    console.log('[HybridEnclave] Executing code in enclave...');

    // Encrypt context with all protocol requirements
    const { payload, seq } = await this.secureSeal(context, AAD.EXECUTE);

    // Send to worker
    const startTime = performance.now();

    const response: any = await this.sendMessageAndWait({
      type: MessageType.EXECUTE,
      code: code,
      encryptedContext: payload,
      seq: seq
    });

    const totalDuration = performance.now() - startTime;

    // Decrypt result with AAD
    const { body: result } = await open(
      this.sessionKey,
      deserializePayload(response.encryptedResult),
      AAD.EXECUTE_RESULT
    );

    // Update metrics
    this.updateMetrics(response.metrics);

    console.log(`[HybridEnclave] Execution complete in ${totalDuration.toFixed(2)}ms`);
    console.log(`[HybridEnclave] Key exposure window: ${response.metrics.keyExposureMs.toFixed(2)}ms`);

    return {
      result,
      metrics: response.metrics,
      totalDurationMs: totalDuration
    };
  }

  /**
   * Sign a transaction with an encrypted private key
   */
  async signTransaction(encryptedKey, transaction) {
    this.ensureInitialized();

    console.log('[HybridEnclave] Signing transaction in enclave...');

    // Encrypt key and transaction with separate sequences
    const key = await this.secureSeal(
      { encryptedKey: Array.from(encryptedKey) },
      AAD.SIGN_TRANSACTION_KEY
    );
    const tx = await this.secureSeal(
      transaction,
      AAD.SIGN_TRANSACTION_TX
    );

    const startTime = performance.now();

    const response: any = await this.sendMessageAndWait({
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
    this.updateMetrics(response.metrics);

    console.log(`[HybridEnclave] Signing complete in ${totalDuration.toFixed(2)}ms`);
    console.log(`[HybridEnclave] Key exposure window: ${response.metrics.keyExposureMs.toFixed(2)}ms`);

    return {
      signature,
      metrics: response.metrics,
      totalDurationMs: totalDuration
    };
  }

  /**
   * Get current metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      averageKeyExposureMs: this.metrics.operationsCount > 0
        ? this.metrics.totalKeyExposureMsSum / this.metrics.operationsCount
        : 0
    };
  }

  /**
   * Update metrics with execution data
   */
  updateMetrics(executionMetrics) {
    this.metrics.operationsCount++;
    this.metrics.totalKeyExposureMsSum += executionMetrics.keyExposureMs;
  }

  /**
   * Send message to worker and wait for response
   */
  sendMessageAndWait(payload, timeout = 30000) {
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
      this.worker!.postMessage({
        id,
        ...payload
      });
    });
  }

  /**
   * Handle messages from worker
   */
  handleWorkerMessage(event) {
    const message = event.data;

    // Find pending request
    const pending = this.pendingRequests.get(message.id);
    if (!pending) {
      console.warn('[HybridEnclave] Received message for unknown request:', message.id);
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
   */
  handleWorkerError(event) {
    console.error('[HybridEnclave] Worker error:', event);

    // Reject all pending requests
    for (const [id, pending] of this.pendingRequests) {
      pending.reject(new Error('Worker error'));
    }
    this.pendingRequests.clear();
  }

  /**
   * Ensure enclave is initialized
   */
  ensureInitialized() {
    if (!this.initialized) {
      throw new Error('Enclave not initialized. Call initialize() first.');
    }
  }

  /**
   * Clean up resources
   */
  destroy() {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.pendingRequests.clear();
    this.initialized = false;
  }
}
