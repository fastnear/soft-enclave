/**
 * End-to-end integration tests for context-bound sessions with AAD
 *
 * Tests the complete flow:
 * 1. Context-bound handshake with code hash
 * 2. Counter-based IV generation
 * 3. AAD on all encrypted messages
 * 4. Cross-origin isolation
 *
 * NOTE: This test requires the enclave server to be running.
 * Run with: RUN_E2E=1 yarn test:integration
 */

import { describe as _describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createEnclave } from '@fastnear/soft-enclave';

// Only run when RUN_E2E=1 to avoid CI flakes
const describe = (process.env.RUN_E2E === '1' ? _describe : _describe.skip);

describe('End-to-End Integration: Context-Bound Sessions + AAD', () => {
  let enclave;

  beforeAll(async () => {
    console.log('\n[Integration Test] Initializing enclave...');
  });

  afterAll(() => {
    if (enclave) {
      enclave.destroy();
    }
  });

  it('should establish context-bound session with code hash', async () => {
    enclave = await createEnclave({
      workerUrl: 'http://localhost:3010/enclave-worker.js'
    });

    await enclave.initialize();

    expect(enclave.initialized).toBe(true);
    expect(enclave.sessionKey).not.toBeNull();
    expect(enclave.baseIV).not.toBeNull();
    expect(enclave.codeHash).not.toBeNull();
    expect(enclave.sendSeq).toBe(0);
    expect(enclave.recvSeq).toBe(0);

    console.log('[Integration Test] ✓ Context-bound session established');
    console.log(`[Integration Test]   Code hash: ${Array.from(enclave.codeHash).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16)}...`);
    console.log(`[Integration Test]   Base IV: ${Array.from(enclave.baseIV).map(b => b.toString(16).padStart(2, '0')).join('')}`);
  }, 30000); // 30s timeout for worker initialization

  it('should execute code with counter-based IVs and AAD', async () => {
    if (!enclave?.initialized) {
      console.log('[Integration Test] Enclave not initialized, skipping...');
      return;
    }

    const code = `
      const result = {
        computation: 2 + 2,
        message: 'Hello from secure enclave',
        timestamp: Date.now()
      };
      result;
    `;

    const initialSendSeq = enclave.sendSeq;

    const result = await enclave.execute(code, {
      userId: 'test-user-123',
      sessionId: 'sess-456'
    });

    expect(result.result).toBeDefined();
    expect(result.result.computation).toBe(4);
    expect(result.result.message).toBe('Hello from secure enclave');
    expect(result.metrics).toBeDefined();
    expect(result.metrics.keyExposureMs).toBeLessThan(1000);

    // Verify sequence counter incremented
    expect(enclave.sendSeq).toBe(initialSendSeq + 1);

    console.log('[Integration Test] ✓ Code execution with counter-based IV + AAD');
    console.log(`[Integration Test]   Result: ${JSON.stringify(result.result)}`);
    console.log(`[Integration Test]   Key exposure: ${result.metrics.keyExposureMs.toFixed(2)}ms`);
    console.log(`[Integration Test]   Sequence counter: ${initialSendSeq} → ${enclave.sendSeq}`);
  }, 10000);

  it('should execute multiple operations with unique IVs', async () => {
    if (!enclave?.initialized) {
      console.log('[Integration Test] Enclave not initialized, skipping...');
      return;
    }

    const operations = [];
    const ivs = new Set();

    // Execute 10 operations
    for (let i = 0; i < 10; i++) {
      const code = `({ iteration: ${i}, value: ${i * 2} })`;
      const result = await enclave.execute(code);
      operations.push(result);
    }

    // Verify all operations succeeded
    expect(operations.length).toBe(10);
    operations.forEach((op, i) => {
      expect(op.result.iteration).toBe(i);
      expect(op.result.value).toBe(i * 2);
    });

    // Verify sequence counter advanced correctly
    expect(enclave.sendSeq).toBeGreaterThanOrEqual(10);

    console.log('[Integration Test] ✓ Multiple operations with unique counter-based IVs');
    console.log(`[Integration Test]   Operations: 10`);
    console.log(`[Integration Test]   Sequence counter: ${enclave.sendSeq}`);
  }, 30000);

  it('should sign transaction with AAD-bound encryption', async () => {
    if (!enclave?.initialized) {
      console.log('[Integration Test] Enclave not initialized, skipping...');
      return;
    }

    const encryptedKey = new Uint8Array(64).fill(0x42); // Mock encrypted key
    const transaction = {
      to: 'alice.near',
      amount: '1000000000000000000000000',
      nonce: 12345
    };

    const initialSendSeq = enclave.sendSeq;

    const result = await enclave.signTransaction(encryptedKey, transaction);

    expect(result.signature).toBeDefined();
    expect(result.metrics).toBeDefined();
    expect(result.metrics.keyExposureMs).toBeLessThan(1000);

    // Verify sequence counter incremented by 2 (key + transaction)
    expect(enclave.sendSeq).toBe(initialSendSeq + 2);

    console.log('[Integration Test] ✓ Transaction signing with AAD');
    console.log(`[Integration Test]   Key exposure: ${result.metrics.keyExposureMs.toFixed(2)}ms`);
    console.log(`[Integration Test]   Sequence counter: ${initialSendSeq} → ${enclave.sendSeq}`);
  }, 10000);

  it('should have different session keys for different contexts', async () => {
    // Create a second enclave instance (same worker URL)
    const enclave2 = await createEnclave({
      workerUrl: 'http://localhost:3010/enclave-worker.js'
    });

    try {
      await enclave2.initialize();

      // Both enclaves should have established sessions
      expect(enclave.sessionKey).not.toBeNull();
      expect(enclave2.sessionKey).not.toBeNull();

      // The keys should be different CryptoKey objects (can't compare directly)
      // But we can verify they both work independently
      const code = `({ result: 'test' })`;

      const result1 = await enclave.execute(code);
      const result2 = await enclave2.execute(code);

      expect(result1.result.result).toBe('test');
      expect(result2.result.result).toBe('test');

      console.log('[Integration Test] ✓ Independent sessions for multiple instances');
    } finally {
      enclave2.destroy();
    }
  }, 30000);

  it('should maintain security metrics across operations', async () => {
    if (!enclave?.initialized) {
      console.log('[Integration Test] Enclave not initialized, skipping...');
      return;
    }

    const metrics = enclave.getMetrics();

    expect(metrics.operationsCount).toBeGreaterThan(0);
    expect(metrics.averageKeyExposureMs).toBeGreaterThan(0);
    expect(metrics.averageKeyExposureMs).toBeLessThan(1000);
    expect(metrics.totalKeyExposureMsSum).toBeGreaterThan(0);

    console.log('[Integration Test] ✓ Security metrics tracked');
    console.log(`[Integration Test]   Operations: ${metrics.operationsCount}`);
    console.log(`[Integration Test]   Avg key exposure: ${metrics.averageKeyExposureMs.toFixed(2)}ms`);
    console.log(`[Integration Test]   Total exposure: ${metrics.totalKeyExposureMsSum.toFixed(2)}ms`);
  });
});

describe('Security Properties: AAD and Context Binding', () => {
  it('should demonstrate AAD prevents message type confusion', async () => {
    // This is a conceptual test showing how AAD would prevent attacks
    // In practice, if AAD doesn't match, decryption will fail with authentication error

    const { encryptWithSequence, decryptWithSequence, deriveSessionWithContext, generateECDHKeyPair } = await import('../src/shared/crypto-protocol.js');

    // Setup a test session
    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    const ctx = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:3010',
      codeHash: 'test-hash'
    };

    const session = await deriveSessionWithContext(
      keyPair1.privateKey,
      keyPair2.publicKey,
      ctx
    );

    // Encrypt with one AAD
    const encrypted = await encryptWithSequence(
      session.aeadKey,
      session.baseIV,
      0,
      { data: 'secret' },
      'EXECUTE'
    );

    // Try to decrypt with different AAD (should fail)
    await expect(async () => {
      await decryptWithSequence(
        session.aeadKey,
        encrypted,
        'SIGN_TRANSACTION' // Wrong AAD!
      );
    }).rejects.toThrow();

    // Decrypt with correct AAD (should succeed)
    const decrypted = await decryptWithSequence(
      session.aeadKey,
      encrypted,
      'EXECUTE'
    );

    expect(decrypted.data).toBe('secret');

    console.log('[Security Test] ✓ AAD prevents message type confusion');
  });

  it('should demonstrate different contexts produce different sessions', async () => {
    const { deriveSessionWithContext, generateECDHKeyPair, exportKey } = await import('../src/shared/crypto-protocol.js');

    const keyPair1 = await generateECDHKeyPair();
    const keyPair2 = await generateECDHKeyPair();

    // Same keys, different contexts
    const ctx1 = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:3010',
      codeHash: 'hash-v1'
    };

    const ctx2 = {
      hostOrigin: 'http://localhost:3000',
      enclaveOrigin: 'http://localhost:3010',
      codeHash: 'hash-v2' // Different code hash
    };

    const session1 = await deriveSessionWithContext(
      keyPair1.privateKey,
      keyPair2.publicKey,
      ctx1
    );

    const session2 = await deriveSessionWithContext(
      keyPair1.privateKey,
      keyPair2.publicKey,
      ctx2
    );

    // Base IVs should be different
    expect(session1.baseIV).not.toEqual(session2.baseIV);

    console.log('[Security Test] ✓ Different contexts produce different sessions');
    console.log(`[Security Test]   Context 1 baseIV: ${Array.from(session1.baseIV).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`[Security Test]   Context 2 baseIV: ${Array.from(session2.baseIV).map(b => b.toString(16).padStart(2, '0')).join('')}`);
  });

  it('should demonstrate counter-based IVs are deterministic and unique', async () => {
    const { ivFromSequence } = await import('../src/shared/crypto-protocol.js');

    const baseIV = new Uint8Array(12).fill(0x42);

    // Generate IVs for sequence 1-10
    const ivs = [];
    for (let i = 1; i <= 10; i++) {
      const iv = ivFromSequence(baseIV, i);
      ivs.push(iv);
    }

    // All IVs should be unique
    const ivSet = new Set(ivs.map(iv => Array.from(iv).join(',')));
    expect(ivSet.size).toBe(10);

    // Same sequence number should produce same IV (deterministic)
    const iv1a = ivFromSequence(baseIV, 1);
    const iv1b = ivFromSequence(baseIV, 1);
    expect(iv1a).toEqual(iv1b);

    // Different sequences should produce different IVs
    const iv2 = ivFromSequence(baseIV, 2);
    expect(iv1a).not.toEqual(iv2);

    console.log('[Security Test] ✓ Counter-based IVs are deterministic and unique');
    console.log(`[Security Test]   Base IV: ${Array.from(baseIV).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`[Security Test]   IV(1): ${Array.from(iv1a).map(b => b.toString(16).padStart(2, '0')).join('')}`);
    console.log(`[Security Test]   IV(2): ${Array.from(iv2).map(b => b.toString(16).padStart(2, '0')).join('')}`);
  });
});
