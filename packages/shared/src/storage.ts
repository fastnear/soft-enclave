/**
 * Storage - Encrypted IndexedDB utilities
 *
 * Provides general-purpose encrypted storage using:
 * - IndexedDB for persistence
 * - AES-GCM encryption for all stored data
 * - Non-extractable encryption keys
 * - Schema versioning and migrations
 *
 * Use Cases:
 * - Application state persistence
 * - Encrypted configuration storage
 * - Transaction history/caching
 * - User preferences
 *
 * Security: All data is encrypted before storage. Keys are non-extractable.
 */

import { openDB, type IDBPDatabase } from 'idb';

/**
 * Database configuration
 */
const DB_NAME = 'soft-enclave-storage';
const DB_VERSION = 1;
const STORE_NAME = 'encrypted-data';

/**
 * Encrypted data record format
 */
export interface EncryptedRecord {
  key: string;
  encryptedValue: ArrayBuffer;
  iv: Uint8Array;
  metadata: {
    createdAt: number;
    updatedAt: number;
    type?: string;
    tags?: string[];
  };
}

/**
 * Storage query options
 */
export interface QueryOptions {
  type?: string;
  tags?: string[];
  limit?: number;
  offset?: number;
}

/**
 * Encrypted storage manager
 */
export class EncryptedStorage {
  private db: IDBPDatabase | null = null;
  private encryptionKey: CryptoKey | null = null;

  constructor() {}

  /**
   * Initialize the storage
   * - Creates IndexedDB database
   * - Generates non-extractable encryption key
   */
  async initialize(): Promise<void> {
    // Open IndexedDB
    this.db = await openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: 'key' });
          store.createIndex('type', 'metadata.type', { unique: false });
          store.createIndex('createdAt', 'metadata.createdAt', { unique: false });
          store.createIndex('updatedAt', 'metadata.updatedAt', { unique: false });
        }
      },
    });

    // Generate non-extractable encryption key
    this.encryptionKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // NOT extractable
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Store encrypted data
   *
   * @param key - Unique identifier for this data
   * @param value - Data to store (will be encrypted)
   * @param type - Optional type tag for categorization
   * @param tags - Optional tags for filtering
   */
  async set(
    key: string,
    value: any,
    type?: string,
    tags?: string[]
  ): Promise<void> {
    if (!this.db || !this.encryptionKey) {
      throw new Error('Storage not initialized');
    }

    // Serialize value to JSON
    const jsonValue = JSON.stringify(value);
    const valueBytes = new TextEncoder().encode(jsonValue);

    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the value
    const encryptedValue = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.encryptionKey,
      valueBytes
    );

    // Create record
    const record: EncryptedRecord = {
      key,
      encryptedValue,
      iv,
      metadata: {
        createdAt: Date.now(),
        updatedAt: Date.now(),
        type,
        tags,
      },
    };

    // Store in IndexedDB
    await this.db.put(STORE_NAME, record);
  }

  /**
   * Retrieve and decrypt data
   *
   * @param key - Key to retrieve
   * @returns Decrypted value, or null if not found
   */
  async get<T = any>(key: string): Promise<T | null> {
    if (!this.db || !this.encryptionKey) {
      throw new Error('Storage not initialized');
    }

    const record = await this.db.get(STORE_NAME, key);
    if (!record) {
      return null;
    }

    // Decrypt the value
    const decryptedBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.iv },
      this.encryptionKey,
      record.encryptedValue
    );

    // Deserialize from JSON
    const jsonValue = new TextDecoder().decode(decryptedBytes);
    return JSON.parse(jsonValue) as T;
  }

  /**
   * Update existing data
   * Similar to set() but preserves createdAt timestamp
   */
  async update(
    key: string,
    value: any,
    type?: string,
    tags?: string[]
  ): Promise<void> {
    if (!this.db || !this.encryptionKey) {
      throw new Error('Storage not initialized');
    }

    // Get existing record to preserve createdAt
    const existingRecord = await this.db.get(STORE_NAME, key);
    const createdAt = existingRecord?.metadata.createdAt || Date.now();

    // Serialize value to JSON
    const jsonValue = JSON.stringify(value);
    const valueBytes = new TextEncoder().encode(jsonValue);

    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the value
    const encryptedValue = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.encryptionKey,
      valueBytes
    );

    // Create updated record
    const record: EncryptedRecord = {
      key,
      encryptedValue,
      iv,
      metadata: {
        createdAt,
        updatedAt: Date.now(),
        type: type || existingRecord?.metadata.type,
        tags: tags || existingRecord?.metadata.tags,
      },
    };

    // Store in IndexedDB
    await this.db.put(STORE_NAME, record);
  }

  /**
   * Delete data
   */
  async delete(key: string): Promise<void> {
    if (!this.db) {
      throw new Error('Storage not initialized');
    }
    await this.db.delete(STORE_NAME, key);
  }

  /**
   * Check if key exists
   */
  async has(key: string): Promise<boolean> {
    if (!this.db) {
      throw new Error('Storage not initialized');
    }
    const record = await this.db.get(STORE_NAME, key);
    return record !== undefined;
  }

  /**
   * Query records by type or tags
   */
  async query(options: QueryOptions = {}): Promise<Array<{ key: string; value: any }>> {
    if (!this.db || !this.encryptionKey) {
      throw new Error('Storage not initialized');
    }

    let records: EncryptedRecord[];

    // Query by type if specified
    if (options.type) {
      const index = this.db.transaction(STORE_NAME).store.index('type');
      records = await index.getAll(options.type);
    } else {
      records = await this.db.getAll(STORE_NAME);
    }

    // Filter by tags if specified
    if (options.tags && options.tags.length > 0) {
      records = records.filter((record) => {
        const recordTags = record.metadata.tags || [];
        return options.tags!.some((tag) => recordTags.includes(tag));
      });
    }

    // Apply offset and limit
    const offset = options.offset || 0;
    const limit = options.limit || records.length;
    records = records.slice(offset, offset + limit);

    // Decrypt all records
    const results = await Promise.all(
      records.map(async (record) => {
        const decryptedBytes = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: record.iv as any },
          this.encryptionKey!,
          record.encryptedValue
        );
        const jsonValue = new TextDecoder().decode(decryptedBytes);
        return {
          key: record.key,
          value: JSON.parse(jsonValue),
        };
      })
    );

    return results;
  }

  /**
   * Get all keys
   */
  async keys(): Promise<string[]> {
    if (!this.db) {
      throw new Error('Storage not initialized');
    }
    const records = await this.db.getAllKeys(STORE_NAME);
    return records as string[];
  }

  /**
   * Clear all data
   */
  async clear(): Promise<void> {
    if (!this.db) {
      throw new Error('Storage not initialized');
    }
    await this.db.clear(STORE_NAME);
  }

  /**
   * Get storage statistics
   */
  async getStats(): Promise<{
    totalRecords: number;
    typeBreakdown: Record<string, number>;
  }> {
    if (!this.db) {
      throw new Error('Storage not initialized');
    }

    const records = await this.db.getAll(STORE_NAME);
    const typeBreakdown: Record<string, number> = {};

    for (const record of records) {
      const type = record.metadata.type || 'untyped';
      typeBreakdown[type] = (typeBreakdown[type] || 0) + 1;
    }

    return {
      totalRecords: records.length,
      typeBreakdown,
    };
  }

  /**
   * Export all data (encrypted) for backup
   * Returns encrypted data that can be re-imported
   */
  async export(): Promise<EncryptedRecord[]> {
    if (!this.db) {
      throw new Error('Storage not initialized');
    }
    return await this.db.getAll(STORE_NAME);
  }

  /**
   * Import encrypted data from backup
   * Note: This requires the same encryption key, so only works in same session
   */
  async import(records: EncryptedRecord[]): Promise<void> {
    if (!this.db) {
      throw new Error('Storage not initialized');
    }

    const tx = this.db.transaction(STORE_NAME, 'readwrite');
    await Promise.all(records.map((record) => tx.store.put(record)));
    await tx.done;
  }

  /**
   * Close the storage and clean up
   */
  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    this.encryptionKey = null;
  }
}

/**
 * Singleton storage instance for convenience
 */
let globalStorage: EncryptedStorage | null = null;

/**
 * Get or create global storage instance
 */
export async function getStorage(): Promise<EncryptedStorage> {
  if (!globalStorage) {
    globalStorage = new EncryptedStorage();
    await globalStorage.initialize();
  }
  return globalStorage;
}

/**
 * Close global storage
 */
export async function closeStorage(): Promise<void> {
  if (globalStorage) {
    await globalStorage.close();
    globalStorage = null;
  }
}
