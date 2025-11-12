/**
 * Tests for crypto protocol
 */

import { describe, it, expect } from 'vitest';
import {
  generateNonExtractableKey,
  generateExtractableKey,
  exportKey,
  importKey,
  encrypt,
  decrypt,
  generateECDHKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveSharedKey,
  serializePayload,
  deserializePayload,
  secureZero,
  measureTiming
} from '@fastnear/soft-enclave-shared';

describe('Crypto Protocol', () => {
  it('should generate non-extractable key', async () => {
    const key = await generateNonExtractableKey();
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(key.extractable).toBe(false);
  });

  it('should generate extractable key', async () => {
    const key = await generateExtractableKey();
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(key.extractable).toBe(true);
  });

  it('should export and import key', async () => {
    const key = await generateExtractableKey();
    const exported = await exportKey(key);
    expect(exported).toBeInstanceOf(Uint8Array);
    expect(exported.length).toBe(32); // 256 bits

    const imported = await importKey(exported);
    expect(imported.type).toBe('secret');
  });

  it('should encrypt and decrypt data', async () => {
    const key = await generateExtractableKey();
    const data = { message: 'Hello, World!', value: 42 };

    const encrypted = await encrypt(key, data);
    expect(encrypted.iv).toBeInstanceOf(Uint8Array);
    expect(encrypted.ciphertext).toBeInstanceOf(Uint8Array);
    expect(encrypted.iv.length).toBe(12);

    const decrypted = await decrypt(key, encrypted);
    expect(decrypted).toEqual(data);
  });

  it('should fail to decrypt with wrong key', async () => {
    const key1 = await generateExtractableKey();
    const key2 = await generateExtractableKey();
    const data = { message: 'Secret!' };

    const encrypted = await encrypt(key1, data);

    await expect(decrypt(key2, encrypted)).rejects.toThrow();
  });

  it('should perform ECDH key exchange', async () => {
    // Alice generates key pair
    const aliceKeyPair = await generateECDHKeyPair();
    const alicePublicKey = await exportPublicKey(aliceKeyPair.publicKey);

    // Bob generates key pair
    const bobKeyPair = await generateECDHKeyPair();
    const bobPublicKey = await exportPublicKey(bobKeyPair.publicKey);

    // Import each other's public keys
    const aliceImportedBobPublic = await importPublicKey(bobPublicKey);
    const bobImportedAlicePublic = await importPublicKey(alicePublicKey);

    // Derive shared keys
    const aliceSharedKey = await deriveSharedKey(
      aliceKeyPair.privateKey,
      aliceImportedBobPublic
    );
    const bobSharedKey = await deriveSharedKey(
      bobKeyPair.privateKey,
      bobImportedAlicePublic
    );

    // Both should be able to encrypt/decrypt with their shared keys
    const data = { message: 'Shared secret' };
    const encrypted = await encrypt(aliceSharedKey, data);
    const decrypted = await decrypt(bobSharedKey, encrypted);

    expect(decrypted).toEqual(data);
  });

  it('should serialize and deserialize payloads', async () => {
    const key = await generateExtractableKey();
    const data = { test: 'data' };

    const encrypted = await encrypt(key, data);
    const serialized = serializePayload(encrypted);

    // Serialized should be plain objects/arrays (for postMessage)
    expect(Array.isArray(serialized.iv)).toBe(true);
    expect(Array.isArray(serialized.ciphertext)).toBe(true);

    const deserialized = deserializePayload(serialized);
    expect(deserialized.iv).toBeInstanceOf(Uint8Array);
    expect(deserialized.ciphertext).toBeInstanceOf(Uint8Array);

    const decrypted = await decrypt(key, deserialized);
    expect(decrypted).toEqual(data);
  });

  it('should securely zero buffers', () => {
    const buffer = new Uint8Array([1, 2, 3, 4, 5]);
    secureZero(buffer);

    expect(Array.from(buffer)).toEqual([0, 0, 0, 0, 0]);
  });

  it('should measure timing accurately', async () => {
    const result = await measureTiming(async () => {
      // Simulate some work
      await new Promise(resolve => setTimeout(resolve, 10));
      return 'done';
    });

    expect(result.result).toBe('done');
    expect(result.duration).toBeGreaterThanOrEqual(9); // Allow some timer variance
    expect(result.durationMs).toBeGreaterThanOrEqual(9);
  });

  it('should ensure encryption adds randomness (different IVs)', async () => {
    const key = await generateExtractableKey();
    const data = { message: 'Same data' };

    const encrypted1 = await encrypt(key, data);
    const encrypted2 = await encrypt(key, data);

    // IVs should be different
    expect(Array.from(encrypted1.iv)).not.toEqual(Array.from(encrypted2.iv));

    // But both should decrypt to same data
    const decrypted1 = await decrypt(key, encrypted1);
    const decrypted2 = await decrypt(key, encrypted2);

    expect(decrypted1).toEqual(data);
    expect(decrypted2).toEqual(data);
  });
});
