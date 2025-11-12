/**
 * Standalone Demo Patterns Tests
 *
 * Tests for patterns from the standalone-wasm-enclave demo:
 * 1. Counter-based IV management
 * 2. Context-bound session derivation
 * 3. AAD message binding
 *
 * These patterns were provided by an external security expert and represent
 * production-quality implementations.
 */

import { describe, it, expect } from 'vitest';
import {
  sha256,
  encodeUtf8,
  decodeUtf8,
  ivFromSequence,
  deriveSessionWithContext,
  encryptWithSequence,
  decryptWithSequence,
  generateECDHKeyPair,
  exportPublicKey,
  importPublicKey,
  serializePayload,
  deserializePayload,
} from '@fastnear/soft-enclave-shared';

describe('Counter-Based IV Management', () => {
  it('should generate unique IVs for different sequence numbers', () => {
    const baseIV = new Uint8Array(12).fill(0xAB);

    const iv1 = ivFromSequence(baseIV, 1);
    const iv2 = ivFromSequence(baseIV, 2);
    const iv3 = ivFromSequence(baseIV, 3);

    // All IVs should be different
    expect(iv1).not.toEqual(iv2);
    expect(iv2).not.toEqual(iv3);
    expect(iv1).not.toEqual(iv3);

    console.log('[Counter IV] seq=1:', Array.from(iv1).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('[Counter IV] seq=2:', Array.from(iv2).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log('[Counter IV] seq=3:', Array.from(iv3).map(b => b.toString(16).padStart(2, '0')).join(''));
  });

  it('should be deterministic - same seq produces same IV', () => {
    const baseIV = new Uint8Array(12).fill(0);

    const iv1a = ivFromSequence(baseIV, 42);
    const iv1b = ivFromSequence(baseIV, 42);

    expect(iv1a).toEqual(iv1b);

    console.log('[Counter IV] Deterministic: seq=42 produces same IV');
  });

  it('should handle large sequence numbers', () => {
    const baseIV = new Uint8Array(12).fill(0);

    const iv1 = ivFromSequence(baseIV, 1);
    const iv2 = ivFromSequence(baseIV, 0xFFFFFFFF); // Max 32-bit

    expect(iv1).not.toEqual(iv2);

    // Last 4 bytes should be XORed with sequence
    expect(iv2[11]).toBe(0xFF);
    expect(iv2[10]).toBe(0xFF);
    expect(iv2[9]).toBe(0xFF);
    expect(iv2[8]).toBe(0xFF);

    console.log('[Counter IV] Max sequence:', Array.from(iv2).map(b => b.toString(16).padStart(2, '0')).join(''));
  });

  it('should only modify last 4 bytes', () => {
    const baseIV = new Uint8Array(12).fill(0xAA);

    const iv = ivFromSequence(baseIV, 0x12345678);

    // First 8 bytes should be unchanged
    for (let i = 0; i < 8; i++) {
      expect(iv[i]).toBe(0xAA);
    }

    // Last 4 bytes should be XORed
    expect(iv[8]).toBe(0xAA ^ 0x12);
    expect(iv[9]).toBe(0xAA ^ 0x34);
    expect(iv[10]).toBe(0xAA ^ 0x56);
    expect(iv[11]).toBe(0xAA ^ 0x78);

    console.log('[Counter IV] Only last 4 bytes modified ✓');
  });

  it('should reject invalid baseIV length', () => {
    const invalidIV = new Uint8Array(10); // Not 12 bytes

    expect(() => ivFromSequence(invalidIV, 1)).toThrow('baseIV must be 12 bytes');
  });

  it('should handle sequence wraparound', () => {
    const baseIV = new Uint8Array(12).fill(0);

    // These should produce different IVs even with wraparound
    const iv1 = ivFromSequence(baseIV, 1);
    const iv2 = ivFromSequence(baseIV, 2);
    const iv3 = ivFromSequence(baseIV, 0x100000001); // Wraps to 1

    // seq=0x100000001 wraps to 1 (32-bit), so should match seq=1
    expect(iv1).toEqual(iv3);
    expect(iv1).not.toEqual(iv2);

    console.log('[Counter IV] Wraparound handled correctly');
  });
});

describe('Context-Bound Session Derivation', () => {
  it('should derive same session on both sides', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const ctx = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:8081',
      codeHash: 'test-hash-v1'
    };

    // Both sides derive session
    const session1 = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx);
    const session2 = await deriveSessionWithContext(keyPair2.privateKey, keyPair1.publicKey, ctx);

    // Both should have same baseIV
    expect(session1.baseIV).toEqual(session2.baseIV);

    // Can encrypt/decrypt between them
    const plaintext = { message: 'test', value: 42 };
    const encrypted = await encryptWithSequence(session1.aeadKey, session1.baseIV, 1, plaintext, 'test');
    const decrypted = await decryptWithSequence(session2.aeadKey, encrypted, 'test');

    expect(decrypted).toEqual(plaintext);

    console.log('[Session Derivation] Both sides derived same session ✓');
  });

  it('should produce different sessions for different contexts', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const ctx1 = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:8081',
      codeHash: 'v1'
    };

    const ctx2 = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:8081',
      codeHash: 'v2' // Different code hash
    };

    const session1 = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx1);
    const session2 = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx2);

    // Different code hash → different session
    expect(session1.baseIV).not.toEqual(session2.baseIV);

    console.log('[Session Derivation] Different contexts produce different sessions ✓');
  });

  it('should bind to host origin', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const ctx1 = { hostOrigin: 'http://localhost:3000', enclaveOrigin: 'http://localhost:8081', codeHash: 'v1' };
    const ctx2 = { hostOrigin: 'http://attacker.com', enclaveOrigin: 'http://localhost:8081', codeHash: 'v1' };

    const session1 = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx1);
    const session2 = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx2);

    // Different host origin → different session
    expect(session1.baseIV).not.toEqual(session2.baseIV);

    console.log('[Session Derivation] Bound to host origin ✓');
  });

  it('should bind to enclave origin', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const ctx1 = { hostOrigin: 'http://localhost:3000', enclaveOrigin: 'http://localhost:8081', codeHash: 'v1' };
    const ctx2 = { hostOrigin: 'http://localhost:3000', enclaveOrigin: 'http://evil.com', codeHash: 'v1' };

    const session1 = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx1);
    const session2 = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx2);

    // Different enclave origin → different session
    expect(session1.baseIV).not.toEqual(session2.baseIV);

    console.log('[Session Derivation] Bound to enclave origin ✓');
  });

  it('should handle empty context gracefully', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const session = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, {});

    expect(session.aeadKey).toBeDefined();
    expect(session.baseIV).toBeDefined();
    expect(session.baseIV.length).toBe(12);

    console.log('[Session Derivation] Empty context handled ✓');
  });

  it('should produce non-extractable AEAD key', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const session = await deriveSessionWithContext(
      keyPair1.privateKey,
      keyPair2.publicKey,
      { codeHash: 'test' }
    );

    expect(session.aeadKey.extractable).toBe(false);
    expect(session.aeadKey.type).toBe('secret');

    console.log('[Session Derivation] AEAD key is non-extractable ✓');
  });
});

describe('Counter-Based Encryption/Decryption', () => {
  it('should encrypt and decrypt with sequence number', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const ctx = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:8081',
      codeHash: 'test'
    };

    const session = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx);

    const plaintext = { message: 'Hello, enclave!', number: 42 };
    const seq = 1;

    const encrypted = await encryptWithSequence(session.aeadKey, session.baseIV, seq, plaintext);
    const decrypted = await decryptWithSequence(session.aeadKey, encrypted);

    expect(decrypted).toEqual(plaintext);

    console.log('[Counter Encryption] Encrypt/decrypt successful ✓');
  });

  it('should support AAD (Additional Authenticated Data)', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const session = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, {});

    const plaintext = { data: 'test' };
    const aad = 'op=evalQuickJS';

    const encrypted = await encryptWithSequence(session.aeadKey, session.baseIV, 1, plaintext, aad);

    // Should decrypt with correct AAD
    const decrypted = await decryptWithSequence(session.aeadKey, encrypted, aad);
    expect(decrypted).toEqual(plaintext);

    // Should fail with wrong AAD
    await expect(
      decryptWithSequence(session.aeadKey, encrypted, 'wrong-aad')
    ).rejects.toThrow();

    console.log('[Counter Encryption] AAD verified ✓');
  });

  it('should produce different ciphertexts for different sequence numbers', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const session = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, {});

    const plaintext = { same: 'data' };

    const encrypted1 = await encryptWithSequence(session.aeadKey, session.baseIV, 1, plaintext);
    const encrypted2 = await encryptWithSequence(session.aeadKey, session.baseIV, 2, plaintext);

    // Different sequence → different IV → different ciphertext
    expect(encrypted1.iv).not.toEqual(encrypted2.iv);
    expect(encrypted1.ciphertext).not.toEqual(encrypted2.ciphertext);

    // But both decrypt to same plaintext
    const decrypted1 = await decryptWithSequence(session.aeadKey, encrypted1);
    const decrypted2 = await decryptWithSequence(session.aeadKey, encrypted2);

    expect(decrypted1).toEqual(plaintext);
    expect(decrypted2).toEqual(plaintext);

    console.log('[Counter Encryption] Different seq → different ciphertext ✓');
  });

  it('should serialize and deserialize for postMessage', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const session = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, {});

    const plaintext = { test: 'data' };
    const encrypted = await encryptWithSequence(session.aeadKey, session.baseIV, 1, plaintext);

    // Serialize for postMessage
    const serialized = serializePayload(encrypted);
    expect(Array.isArray(serialized.iv)).toBe(true);
    expect(Array.isArray(serialized.ciphertext)).toBe(true);

    // Deserialize
    const deserialized = deserializePayload(serialized);
    expect(deserialized.iv).toBeInstanceOf(Uint8Array);
    expect(deserialized.ciphertext).toBeInstanceOf(Uint8Array);

    // Should decrypt after roundtrip
    const decrypted = await decryptWithSequence(session.aeadKey, deserialized);
    expect(decrypted).toEqual(plaintext);

    console.log('[Counter Encryption] Serialization roundtrip ✓');
  });
});

describe('SHA-256 and UTF-8 Helpers', () => {
  it('should compute SHA-256 hash', async () => {
    const input = encodeUtf8('test input');
    const hash = await sha256(input);

    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32); // SHA-256 = 32 bytes

    // Should be deterministic
    const hash2 = await sha256(input);
    expect(hash).toEqual(hash2);

    console.log('[SHA-256] Hash:', Array.from(hash.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
  });

  it('should encode and decode UTF-8', () => {
    const str = 'Hello, 世界! 🚀';

    const encoded = encodeUtf8(str);
    expect(encoded).toBeInstanceOf(Uint8Array);

    const decoded = decodeUtf8(encoded);
    expect(decoded).toBe(str);

    console.log('[UTF-8] Roundtrip successful for:', str);
  });

  it('should handle empty strings', () => {
    const encoded = encodeUtf8('');
    expect(encoded.length).toBe(0);

    const decoded = decodeUtf8(new Uint8Array());
    expect(decoded).toBe('');
  });
});

describe('Real-World Usage Pattern', () => {
  it('should simulate host-enclave encrypted session', async () => {
    console.log('\n[Real-World Test] Simulating host-enclave session...');

    // 1. Both generate keypairs
    const hostKeys = await generateECDHKeyPair();
    const enclaveKeys = await generateECDHKeyPair();

    console.log('  1. Generated keypairs');

    // 2. Exchange public keys (simulate postMessage)
    const hostPub = await exportPublicKey(hostKeys.publicKey);
    const enclavePub = await exportPublicKey(enclaveKeys.publicKey);

    console.log('  2. Exchanged public keys');

    // 3. Both derive session with same context
    const ctx = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:8081',
      codeHash: 'abc123def456'
    };

    const hostSession = await deriveSessionWithContext(hostKeys.privateKey, await importPublicKey(enclavePub), ctx);
    const enclaveSession = await deriveSessionWithContext(enclaveKeys.privateKey, await importPublicKey(hostPub), ctx);

    console.log('  3. Both derived session');

    // 4. Host sends encrypted command
    let hostSeq = 1;
    const command = { op: 'evalQuickJS', code: 'function fib(n){return n<=1?n:fib(n-1)+fib(n-2);} fib(10)' };
    const encryptedCommand = await encryptWithSequence(hostSession.aeadKey, hostSession.baseIV, hostSeq++, command, 'op=evalQuickJS');

    console.log('  4. Host encrypted command (seq=1)');

    // 5. Enclave receives and decrypts
    const decryptedCommand = await decryptWithSequence(enclaveSession.aeadKey, encryptedCommand, 'op=evalQuickJS');
    expect(decryptedCommand).toEqual(command);

    console.log('  5. Enclave decrypted command');

    // 6. Enclave sends encrypted result
    let enclaveSeq = 1;
    const result = { ok: true, value: 55 };
    const encryptedResult = await encryptWithSequence(enclaveSession.aeadKey, enclaveSession.baseIV, enclaveSeq++, result, 'op=evalQuickJS:result');

    console.log('  6. Enclave encrypted result (seq=1)');

    // 7. Host receives and decrypts
    const decryptedResult = await decryptWithSequence(hostSession.aeadKey, encryptedResult, 'op=evalQuickJS:result');
    expect(decryptedResult).toEqual(result);

    console.log('  7. Host decrypted result');
    console.log('  ✓ Full encrypted session completed successfully!');
  });

  it('should prevent cross-context attacks', async () => {
    const hostKeys = await generateECDHKeyPair();
    const enclaveKeys = await generateECDHKeyPair();

    // Legitimate session
    const ctx1 = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:8081',
      codeHash: 'legitimate-v1'
    };

    const session1 = await deriveSessionWithContext(hostKeys.privateKey, enclaveKeys.publicKey, ctx1);

    // Attacker tries to use different context
    const ctx2 = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:8081',
      codeHash: 'malicious-v2' // Different code hash
    };

    const session2 = await deriveSessionWithContext(hostKeys.privateKey, enclaveKeys.publicKey, ctx2);

    // Encrypt with session1
    const encrypted = await encryptWithSequence(session1.aeadKey, session1.baseIV, 1, { data: 'test' });

    // Try to decrypt with session2 (should fail)
    await expect(
      decryptWithSequence(session2.aeadKey, encrypted)
    ).rejects.toThrow();

    console.log('[Security] Cross-context attack prevented ✓');
  });
});

describe('Performance Benchmarks', () => {
  it('should benchmark session derivation', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();
    const ctx = { hostOrigin: 'http://localhost:3000', enclaveOrigin: 'http://localhost:8081', codeHash: 'test' };

    const iterations = 100;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, ctx);
    }

    const duration = performance.now() - start;
    const avgMs = duration / iterations;

    console.log(`[Benchmark] Session derivation: ${avgMs.toFixed(2)}ms per operation (${iterations} iterations)`);

    expect(avgMs).toBeLessThan(50); // Should be reasonably fast
  });

  it('should benchmark counter-based encryption', async () => {
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const session = await deriveSessionWithContext(keyPair1.privateKey, keyPair2.publicKey, {});
    const plaintext = { message: 'benchmark test', value: 42 };

    const iterations = 1000;
    const start = performance.now();

    for (let i = 1; i <= iterations; i++) {
      await encryptWithSequence(session.aeadKey, session.baseIV, i, plaintext, 'test');
    }

    const duration = performance.now() - start;
    const avgMs = duration / iterations;

    console.log(`[Benchmark] Counter-based encryption: ${avgMs.toFixed(3)}ms per operation (${iterations} iterations)`);

    expect(avgMs).toBeLessThan(2); // Should be fast
  });
});
