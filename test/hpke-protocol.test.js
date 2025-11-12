/**
 * HPKE Protocol Tests
 *
 * Verifies the HPKE (RFC 9180) implementation:
 * - Key generation and serialization
 * - Encryption and decryption
 * - AAD (Additional Authenticated Data) support
 * - Code attestation binding
 * - No nonce reuse issues (handled by HPKE internally)
 */

import { describe, it, expect } from 'vitest';
import {
  generateHPKEKeyPair,
  hpkeEncrypt,
  hpkeDecrypt,
  serializePublicKey,
  deserializePublicKey,
  serializeHPKEMessage,
  deserializeHPKEMessage,
  hpkeEncryptWithAttestation,
  hpkeDecryptWithAttestation,
  deriveCodeHash,
  isHPKEMessage,
  isLegacyMessage,
} from '@fastnear/soft-enclave-shared';

// Gate experimental HPKE tests behind environment variable
const _describe = (process.env.RUN_HPKE === '1') ? describe : describe.skip;

_describe('HPKE: Key Generation and Serialization', () => {
  it('should generate HPKE key pair', async () => {
    const keyPair = await generateHPKEKeyPair();

    expect(keyPair).toBeDefined();
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);

    // X25519 keys are 32 bytes
    expect(keyPair.privateKey.length).toBe(32);
    expect(keyPair.publicKey.length).toBe(32);

    console.log('[HPKE Test] Generated key pair:', {
      privateKeyLength: keyPair.privateKey.length,
      publicKeyLength: keyPair.publicKey.length
    });
  });

  it('should serialize and deserialize public key', async () => {
    const keyPair = await generateHPKEKeyPair();

    // Serialize for postMessage
    const serialized = serializePublicKey(keyPair.publicKey);

    expect(Array.isArray(serialized)).toBe(true);
    expect(serialized.length).toBe(32);

    // Deserialize after postMessage
    const deserialized = deserializePublicKey(serialized);

    expect(deserialized).toBeInstanceOf(Uint8Array);
    expect(deserialized.length).toBe(32);

    // Should be identical
    expect(Array.from(deserialized)).toEqual(Array.from(keyPair.publicKey));

    console.log('[HPKE Test] ✓ Public key serialization roundtrip successful');
  });

  it('should generate different key pairs each time', async () => {
    const keyPair1 = await generateHPKEKeyPair();
    const keyPair2 = await generateHPKEKeyPair();

    // Different private keys
    expect(Array.from(keyPair1.privateKey)).not.toEqual(Array.from(keyPair2.privateKey));

    // Different public keys
    expect(Array.from(keyPair1.publicKey)).not.toEqual(Array.from(keyPair2.publicKey));

    console.log('[HPKE Test] ✓ Key pairs are unique');
  });
});

_describe('HPKE: Encryption and Decryption', () => {
  it('should encrypt and decrypt data successfully', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const plaintext = { message: 'Secret data', value: 12345 };

    // Encrypt
    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext);

    expect(encrypted.enc).toBeInstanceOf(Uint8Array);
    expect(encrypted.ciphertext).toBeInstanceOf(Uint8Array);

    console.log('[HPKE Test] Encrypted:', {
      encLength: encrypted.enc.length,
      ciphertextLength: encrypted.ciphertext.length
    });

    // Decrypt
    const decrypted = await hpkeDecrypt(recipientKeyPair, encrypted);

    expect(decrypted).toEqual(plaintext);

    console.log('[HPKE Test] ✓ Encryption/decryption successful');
  });

  it('should fail to decrypt with wrong private key', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const wrongKeyPair = await generateHPKEKeyPair();
    const plaintext = { message: 'Secret' };

    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext);

    // Should fail with wrong key
    await expect(
      hpkeDecrypt(wrongKeyPair, encrypted)
    ).rejects.toThrow();

    console.log('[HPKE Test] ✓ Wrong key rejection works');
  });

  it('should fail to decrypt tampered ciphertext', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const plaintext = { message: 'Secret' };

    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext);

    // Tamper with ciphertext
    encrypted.ciphertext[0] ^= 0xFF;

    // Should fail authentication
    await expect(
      hpkeDecrypt(recipientKeyPair, encrypted)
    ).rejects.toThrow();

    console.log('[HPKE Test] ✓ Tampered ciphertext rejected');
  });

  it('should serialize and deserialize encrypted messages', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const plaintext = { test: 'data' };

    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext);

    // Serialize for postMessage
    const serialized = serializeHPKEMessage(encrypted);

    expect(Array.isArray(serialized.enc)).toBe(true);
    expect(Array.isArray(serialized.ciphertext)).toBe(true);

    // Deserialize after postMessage
    const deserialized = deserializeHPKEMessage(serialized);

    expect(deserialized.enc).toBeInstanceOf(Uint8Array);
    expect(deserialized.ciphertext).toBeInstanceOf(Uint8Array);

    // Should decrypt successfully
    const decrypted = await hpkeDecrypt(recipientKeyPair, deserialized);
    expect(decrypted).toEqual(plaintext);

    console.log('[HPKE Test] ✓ Message serialization roundtrip successful');
  });
});

_describe('HPKE: Additional Authenticated Data (AAD)', () => {
  it('should encrypt and decrypt with AAD', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const plaintext = { message: 'Secret' };
    const aad = new TextEncoder().encode('context-info');

    // Encrypt with AAD
    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext, aad);

    // Decrypt with same AAD
    const decrypted = await hpkeDecrypt(recipientKeyPair, encrypted, aad);

    expect(decrypted).toEqual(plaintext);

    console.log('[HPKE Test] ✓ AAD encryption/decryption successful');
  });

  it('should fail to decrypt with wrong AAD', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const plaintext = { message: 'Secret' };
    const aad = new TextEncoder().encode('context-1');
    const wrongAad = new TextEncoder().encode('context-2');

    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext, aad);

    // Should fail with different AAD
    await expect(
      hpkeDecrypt(recipientKeyPair, encrypted, wrongAad)
    ).rejects.toThrow();

    console.log('[HPKE Test] ✓ Wrong AAD rejected');
  });

  it('should fail to decrypt AAD-encrypted message without AAD', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const plaintext = { message: 'Secret' };
    const aad = new TextEncoder().encode('required-context');

    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext, aad);

    // Should fail when AAD is omitted
    await expect(
      hpkeDecrypt(recipientKeyPair, encrypted)
    ).rejects.toThrow();

    console.log('[HPKE Test] ✓ Missing AAD rejected');
  });
});

_describe('HPKE: Code Attestation', () => {
  it('should derive consistent code hash', async () => {
    const code = 'function test() { return 42; }';

    const hash1 = await deriveCodeHash(code);
    const hash2 = await deriveCodeHash(code);

    expect(hash1).toBeInstanceOf(Uint8Array);
    expect(hash1.length).toBe(32); // SHA-256 = 32 bytes
    expect(Array.from(hash1)).toEqual(Array.from(hash2));

    console.log('[HPKE Test] Code hash:', Array.from(hash1.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
  });

  it('should derive different hashes for different code', async () => {
    const code1 = 'function test() { return 42; }';
    const code2 = 'function test() { return 43; }';

    const hash1 = await deriveCodeHash(code1);
    const hash2 = await deriveCodeHash(code2);

    expect(Array.from(hash1)).not.toEqual(Array.from(hash2));

    console.log('[HPKE Test] ✓ Different code produces different hashes');
  });

  it('should encrypt and decrypt with code attestation', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const code = 'function fibonacci(n) { return n <= 1 ? n : fibonacci(n-1) + fibonacci(n-2); }';
    const data = { input: 10 };

    // Encrypt with code attestation
    const encrypted = await hpkeEncryptWithAttestation(recipientKeyPair.publicKey, code, data);

    // Decrypt with same code
    const decrypted = await hpkeDecryptWithAttestation(recipientKeyPair, encrypted, code);

    expect(decrypted).toEqual(data);

    console.log('[HPKE Test] ✓ Code attestation encryption/decryption successful');
  });

  it('should fail to decrypt with different code', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const code1 = 'function test1() { }';
    const code2 = 'function test2() { }';
    const data = { value: 123 };

    const encrypted = await hpkeEncryptWithAttestation(recipientKeyPair.publicKey, code1, data);

    // Should fail with different code
    await expect(
      hpkeDecryptWithAttestation(recipientKeyPair, encrypted, code2)
    ).rejects.toThrow();

    console.log('[HPKE Test] ✓ Code mismatch rejected (prevents code substitution attacks)');
  });
});

_describe('HPKE: Nonce Management', () => {
  it('should produce different ciphertexts for same plaintext (implicit nonces)', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const plaintext = { message: 'Same data every time' };

    const encrypted1 = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext);
    const encrypted2 = await hpkeEncrypt(recipientKeyPair.publicKey, plaintext);

    // Encapsulated keys should be different (ephemeral sender keys)
    expect(Array.from(encrypted1.enc)).not.toEqual(Array.from(encrypted2.enc));

    // Ciphertexts should be different
    expect(Array.from(encrypted1.ciphertext)).not.toEqual(Array.from(encrypted2.ciphertext));

    // But both decrypt to same plaintext
    const decrypted1 = await hpkeDecrypt(recipientKeyPair, encrypted1);
    const decrypted2 = await hpkeDecrypt(recipientKeyPair, encrypted2);

    expect(decrypted1).toEqual(plaintext);
    expect(decrypted2).toEqual(plaintext);

    console.log('[HPKE Test] ✓ HPKE handles nonce management internally (no manual IV)');
  });

  it('should never reuse nonces across 1000 encryptions', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const trials = 1000;
    const encSet = new Set();

    console.log('[HPKE Test] Testing nonce uniqueness across 1000 encryptions...');

    for (let i = 0; i < trials; i++) {
      const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, { trial: i });

      const encHex = Array.from(encrypted.enc)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      // Each enc should be unique (ephemeral sender key)
      if (encSet.has(encHex)) {
        throw new Error(`Duplicate enc at trial ${i}!`);
      }

      encSet.add(encHex);
    }

    expect(encSet.size).toBe(trials);
    console.log('[HPKE Test] ✓ All 1000 encapsulated keys unique (HPKE uses ephemeral keys)');
  });
});

_describe('HPKE: Message Format Detection', () => {
  it('should identify HPKE messages', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, { test: true });

    expect(isHPKEMessage(encrypted)).toBe(true);
    expect(isLegacyMessage(encrypted)).toBe(false);

    const serialized = serializeHPKEMessage(encrypted);
    expect(isHPKEMessage(serialized)).toBe(true);
    expect(isLegacyMessage(serialized)).toBe(false);

    console.log('[HPKE Test] ✓ HPKE message detection works');
  });

  it('should identify legacy messages', () => {
    const legacyMessage = {
      iv: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
      ciphertext: [1, 2, 3, 4]
    };

    expect(isHPKEMessage(legacyMessage)).toBe(false);
    expect(isLegacyMessage(legacyMessage)).toBe(true);

    console.log('[HPKE Test] ✓ Legacy message detection works');
  });
});

_describe('HPKE: Performance and Scalability', () => {
  it('should handle large payloads', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();

    // Create large payload (10KB of data)
    const largeData = {
      array: Array(1000).fill({ value: 'test', number: 12345 })
    };

    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, largeData);
    const decrypted = await hpkeDecrypt(recipientKeyPair, encrypted);

    expect(decrypted).toEqual(largeData);

    console.log('[HPKE Test] Large payload:', {
      plaintextSize: JSON.stringify(largeData).length,
      ciphertextSize: encrypted.ciphertext.length
    });
  });

  it('should measure encryption/decryption performance', async () => {
    const recipientKeyPair = await generateHPKEKeyPair();
    const data = { message: 'Performance test', value: 42 };
    const iterations = 100;

    // Measure encryption
    const encryptStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      await hpkeEncrypt(recipientKeyPair.publicKey, data);
    }
    const encryptDuration = performance.now() - encryptStart;

    // Measure decryption
    const encrypted = await hpkeEncrypt(recipientKeyPair.publicKey, data);
    const decryptStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      await hpkeDecrypt(recipientKeyPair, encrypted);
    }
    const decryptDuration = performance.now() - decryptStart;

    console.log('[HPKE Performance]');
    console.log(`  Encryption: ${(encryptDuration / iterations).toFixed(2)}ms per operation`);
    console.log(`  Decryption: ${(decryptDuration / iterations).toFixed(2)}ms per operation`);
    console.log(`  Total: ${((encryptDuration + decryptDuration) / iterations).toFixed(2)}ms per roundtrip`);

    expect(encryptDuration).toBeGreaterThan(0);
    expect(decryptDuration).toBeGreaterThan(0);
  });
});
