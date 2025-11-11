/**
 * Keystore - WebCrypto-based key custody
 *
 * Provides secure key management using:
 * - Non-extractable WebCrypto master keys (primary defense)
 * - AES-GCM key wrapping for private keys
 * - IndexedDB for encrypted key storage
 * - Ephemeral key exposure with timing metrics
 * - Explicit memory zeroing
 *
 * Security Model (Defense-in-Depth):
 * 1. WebCrypto non-extractable keys - Master key cannot be exported
 * 2. Key wrapping - Private keys encrypted before storage
 * 3. Ephemeral unwrapping - Keys decrypted only during operations
 * 4. Memory zeroing - Best-effort cleanup after use
 *
 * IMPORTANT: This is NOT a hardware TEE. See THREAT_MODEL.md for limitations.
 */

import { openDB, type IDBPDatabase } from 'idb';

/**
 * Database schema for encrypted keys
 */
const DB_NAME = 'soft-enclave-keystore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

/**
 * Key metadata stored alongside wrapped keys
 */
export interface KeyMetadata {
  accountId: string;
  publicKey: string;
  createdAt: number;
  lastUsedAt: number;
}

/**
 * Wrapped key storage format
 */
export interface WrappedKey {
  metadata: KeyMetadata;
  wrappedKey: ArrayBuffer;
  iv: Uint8Array;
  salt: Uint8Array;
}

/**
 * Timing metrics for security auditing
 */
export interface KeystoreMetrics {
  operationName: string;
  keyExposureDurationMs: number;
  totalDurationMs: number;
  timestamp: number;
}

/**
 * Keystore for managing NEAR account keys
 */
export class Keystore {
  private db: IDBPDatabase | null = null;
  private masterKey: CryptoKey | null = null;
  private metrics: KeystoreMetrics[] = [];

  constructor() {}

  /**
   * Initialize the keystore
   * - Creates IndexedDB database
   * - Generates or loads master key
   */
  async initialize(): Promise<void> {
    const startTime = performance.now();

    // Open IndexedDB
    this.db = await openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: 'metadata.accountId' });
          store.createIndex('publicKey', 'metadata.publicKey', { unique: true });
        }
      },
    });

    // Generate non-extractable master key
    // This key CANNOT be exported - enforced by browser
    this.masterKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // NOT extractable - critical security property!
      ['wrapKey', 'unwrapKey']
    );

    const totalDuration = performance.now() - startTime;
    this.recordMetric({
      operationName: 'initialize',
      keyExposureDurationMs: 0,
      totalDurationMs: totalDuration,
      timestamp: Date.now(),
    });
  }

  /**
   * Store a NEAR private key securely
   * - Wraps (encrypts) the private key with master key
   * - Stores wrapped key in IndexedDB
   * - Original key is zeroed from memory
   *
   * @param accountId - NEAR account ID
   * @param privateKeyBytes - Ed25519 private key (64 bytes)
   * @param publicKey - Public key in ed25519:base58 format
   */
  async storeKey(
    accountId: string,
    privateKeyBytes: Uint8Array,
    publicKey: string
  ): Promise<void> {
    if (!this.db || !this.masterKey) {
      throw new Error('Keystore not initialized');
    }

    const startTime = performance.now();
    let keyExposureStart = performance.now();

    try {
      // Import private key as CryptoKey (temporarily extractable for wrapping)
      const privateKey = await crypto.subtle.importKey(
        'raw',
        privateKeyBytes as any,
        { name: 'Ed25519' },
        true, // Must be extractable to wrap
        ['sign']
      );

      // Generate random IV and salt for this key
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const salt = crypto.getRandomValues(new Uint8Array(16));

      // Wrap (encrypt) the private key with master key
      const wrappedKey = await crypto.subtle.wrapKey(
        'raw',
        privateKey,
        this.masterKey,
        { name: 'AES-GCM', iv }
      );

      const keyExposureDuration = performance.now() - keyExposureStart;

      // Zero out original key bytes (best effort)
      this.secureZero(privateKeyBytes);

      // Store wrapped key with metadata
      const metadata: KeyMetadata = {
        accountId,
        publicKey,
        createdAt: Date.now(),
        lastUsedAt: Date.now(),
      };

      const wrappedKeyRecord: WrappedKey = {
        metadata,
        wrappedKey,
        iv,
        salt,
      };

      await this.db.put(STORE_NAME, wrappedKeyRecord);

      const totalDuration = performance.now() - startTime;
      this.recordMetric({
        operationName: 'storeKey',
        keyExposureDurationMs: keyExposureDuration,
        totalDurationMs: totalDuration,
        timestamp: Date.now(),
      });
    } catch (error) {
      // Ensure key is zeroed even on error
      this.secureZero(privateKeyBytes);
      throw error;
    }
  }

  /**
   * Sign data with a stored key
   * - Unwraps (decrypts) the private key ephemerally
   * - Signs the data
   * - Immediately disposes the key
   * - Measures key exposure time
   *
   * @param accountId - NEAR account ID
   * @param data - Data to sign
   * @returns Signature bytes
   */
  async sign(accountId: string, data: Uint8Array): Promise<Uint8Array> {
    if (!this.db || !this.masterKey) {
      throw new Error('Keystore not initialized');
    }

    const startTime = performance.now();

    // Load wrapped key from IndexedDB
    const wrappedKeyRecord = await this.db.get(STORE_NAME, accountId);
    if (!wrappedKeyRecord) {
      throw new Error(`Key not found for account: ${accountId}`);
    }

    const keyExposureStart = performance.now();

    try {
      // Unwrap (decrypt) the private key
      const privateKey = await crypto.subtle.unwrapKey(
        'raw',
        wrappedKeyRecord.wrappedKey,
        this.masterKey,
        { name: 'AES-GCM', iv: wrappedKeyRecord.iv },
        { name: 'Ed25519' },
        false, // Not extractable after unwrapping
        ['sign']
      );

      // Sign the data
      const signature = await crypto.subtle.sign('Ed25519', privateKey, data as any);

      const keyExposureDuration = performance.now() - keyExposureStart;

      // Update last used timestamp
      wrappedKeyRecord.metadata.lastUsedAt = Date.now();
      await this.db.put(STORE_NAME, wrappedKeyRecord);

      const totalDuration = performance.now() - startTime;
      this.recordMetric({
        operationName: 'sign',
        keyExposureDurationMs: keyExposureDuration,
        totalDurationMs: totalDuration,
        timestamp: Date.now(),
      });

      return new Uint8Array(signature);
    } catch (error) {
      throw new Error(`Failed to sign with key for ${accountId}: ${error}`);
    }
  }

  /**
   * Get public key for an account
   */
  async getPublicKey(accountId: string): Promise<string | null> {
    if (!this.db) {
      throw new Error('Keystore not initialized');
    }

    const wrappedKeyRecord = await this.db.get(STORE_NAME, accountId);
    return wrappedKeyRecord?.metadata.publicKey || null;
  }

  /**
   * List all stored accounts
   */
  async listAccounts(): Promise<KeyMetadata[]> {
    if (!this.db) {
      throw new Error('Keystore not initialized');
    }

    const allKeys = await this.db.getAll(STORE_NAME);
    return allKeys.map((record) => record.metadata);
  }

  /**
   * Delete a key from storage
   */
  async deleteKey(accountId: string): Promise<void> {
    if (!this.db) {
      throw new Error('Keystore not initialized');
    }

    await this.db.delete(STORE_NAME, accountId);
  }

  /**
   * Get security metrics for auditing
   * Provides timing information for key exposure
   */
  getMetrics(): KeystoreMetrics[] {
    return [...this.metrics];
  }

  /**
   * Clear metrics history
   */
  clearMetrics(): void {
    this.metrics = [];
  }

  /**
   * Get average key exposure time (for security auditing)
   */
  getAverageKeyExposure(): number {
    if (this.metrics.length === 0) return 0;
    const total = this.metrics.reduce((sum, m) => sum + m.keyExposureDurationMs, 0);
    return total / this.metrics.length;
  }

  /**
   * Best-effort memory zeroing
   * Note: JavaScript doesn't guarantee memory overwrite
   */
  private secureZero(buffer: Uint8Array): void {
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = 0;
    }
  }

  /**
   * Record timing metrics
   */
  private recordMetric(metric: KeystoreMetrics): void {
    this.metrics.push(metric);

    // Keep only last 100 metrics to avoid memory bloat
    if (this.metrics.length > 100) {
      this.metrics.shift();
    }
  }

  /**
   * Close the keystore and clean up
   */
  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    this.masterKey = null;
    this.clearMetrics();
  }
}

/**
 * Singleton keystore instance for convenience
 */
let globalKeystore: Keystore | null = null;

/**
 * Get or create global keystore instance
 */
export async function getKeystore(): Promise<Keystore> {
  if (!globalKeystore) {
    globalKeystore = new Keystore();
    await globalKeystore.initialize();
  }
  return globalKeystore;
}

/**
 * Close global keystore
 */
export async function closeKeystore(): Promise<void> {
  if (globalKeystore) {
    await globalKeystore.close();
    globalKeystore = null;
  }
}
