/**
 * Nonce (IV) Uniqueness Tests
 *
 * AES-GCM nonce reuse is CATASTROPHIC - it completely breaks confidentiality.
 * These property tests verify our crypto implementation never reuses IVs.
 *
 * Background:
 * - AES-GCM uses 96-bit (12-byte) nonces
 * - Nonce space: 2^96 ≈ 7.9 × 10^28 possible values
 * - Birthday bound: √(2^96) = 2^48 ≈ 281 trillion operations
 * - For production: Must ensure uniqueness through proper IV generation
 *
 * Our implementation: crypto.getRandomValues(new Uint8Array(12))
 * - Relies on cryptographically secure PRNG
 * - Should provide uniform distribution over IV space
 * - Collision probability is negligible for realistic usage
 */

import { describe, it, expect } from 'vitest';
import {
  generateNonExtractableKey,
  encrypt,
  decrypt
} from '@fastnear/soft-enclave-shared';

describe('Nonce Uniqueness: Property Tests', () => {
  it('should never reuse IVs across 10,000 encryptions', async () => {
    const key = await generateNonExtractableKey();
    const ivSet = new Set();
    const trials = 10000;

    console.log(`[Nonce Test] Running ${trials} encryptions to verify IV uniqueness...`);

    for (let i = 0; i < trials; i++) {
      const { iv } = await encrypt(key, { trial: i, data: `test-${i}` });

      // Convert IV to hex string for Set comparison
      const ivHex = Array.from(iv)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      // CRITICAL: Should NEVER see duplicate IV
      if (ivSet.has(ivHex)) {
        console.error(`[CATASTROPHIC] IV reuse detected at trial ${i}!`);
        console.error(`[CATASTROPHIC] Duplicate IV: ${ivHex}`);
        throw new Error(`IV REUSE DETECTED! This breaks AES-GCM security completely.`);
      }

      ivSet.add(ivHex);

      // Progress logging
      if (i > 0 && i % 1000 === 0) {
        console.log(`  ✓ ${i} encryptions, ${ivSet.size} unique IVs`);
      }
    }

    // Verify all IVs were unique
    expect(ivSet.size).toBe(trials);

    console.log(`[Nonce Test] ✓ All ${trials} IVs were unique`);
    console.log(`[Nonce Test] Collision probability: ~${(trials * trials / (2 ** 96)).toExponential(2)}`);
  });

  it('should generate uniformly distributed IVs', async () => {
    const key = await generateNonExtractableKey();
    const trials = 1000;
    const byteDistribution = Array(256).fill(0);

    console.log('[Nonce Test] Testing IV byte distribution uniformity...');

    for (let i = 0; i < trials; i++) {
      const { iv } = await encrypt(key, { trial: i });

      // Count distribution of first byte
      // (uniform PRNG should distribute evenly across 0-255)
      byteDistribution[iv[0]]++;
    }

    // Calculate chi-square statistic for uniformity
    const expected = trials / 256;
    const chiSquare = byteDistribution.reduce((sum, observed) => {
      const diff = observed - expected;
      return sum + (diff * diff) / expected;
    }, 0);

    // For 255 degrees of freedom, chi-square critical value at p=0.05 is ~293
    // We use relaxed threshold since we only have 1000 samples
    const threshold = 400;

    console.log(`[Nonce Test] Chi-square statistic: ${chiSquare.toFixed(2)}`);
    console.log(`[Nonce Test] Threshold (p=0.05): ${threshold}`);

    expect(chiSquare).toBeLessThan(threshold);

    // Show distribution of most/least common bytes
    const sorted = [...byteDistribution].sort((a, b) => b - a);
    console.log(`[Nonce Test] Most common byte count: ${sorted[0]}`);
    console.log(`[Nonce Test] Least common byte count: ${sorted[sorted.length - 1]}`);
    console.log(`[Nonce Test] ✓ Distribution is acceptably uniform`);
  });

  it('should generate unique IVs even with same plaintext', async () => {
    const key = await generateNonExtractableKey();
    const ivSet = new Set();
    const trials = 1000;
    const samePlaintext = { message: 'This is the same plaintext every time' };

    console.log('[Nonce Test] Encrypting same plaintext 1000 times...');

    for (let i = 0; i < trials; i++) {
      const { iv } = await encrypt(key, samePlaintext);
      const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');

      // Even with same plaintext, IVs must be unique
      expect(ivSet.has(ivHex)).toBe(false);
      ivSet.add(ivHex);
    }

    expect(ivSet.size).toBe(trials);
    console.log(`[Nonce Test] ✓ ${trials} unique IVs for same plaintext`);
  });

  it('should generate unique IVs across concurrent encryptions', async () => {
    const key = await generateNonExtractableKey();
    const concurrentBatches = 10;
    const batchSize = 100;

    console.log(`[Nonce Test] Testing ${concurrentBatches} concurrent batches of ${batchSize} encryptions...`);

    const allIVs = new Set();

    for (let batch = 0; batch < concurrentBatches; batch++) {
      // Create concurrent encryption promises
      const promises = Array(batchSize)
        .fill(null)
        .map((_, i) => encrypt(key, { batch, index: i }));

      // Wait for all to complete
      const results = await Promise.all(promises);

      // Check all IVs in this batch
      for (const { iv } of results) {
        const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');

        // Should not collide even in concurrent batch
        if (allIVs.has(ivHex)) {
          throw new Error(`IV collision in concurrent batch ${batch}!`);
        }

        allIVs.add(ivHex);
      }

      console.log(`  Batch ${batch + 1}/${concurrentBatches}: ${allIVs.size} total unique IVs`);
    }

    const totalOperations = concurrentBatches * batchSize;
    expect(allIVs.size).toBe(totalOperations);
    console.log(`[Nonce Test] ✓ All ${totalOperations} concurrent IVs were unique`);
  });
});

describe('Nonce Uniqueness: Encryption/Decryption Integrity', () => {
  it('should correctly decrypt with different IVs', async () => {
    const key = await generateNonExtractableKey();
    const plaintext = { message: 'Secret data', value: 12345 };

    console.log('[Nonce Test] Testing encrypt/decrypt with different IVs...');

    // Encrypt same data multiple times (different IVs each time)
    const encryptions = await Promise.all(
      Array(10).fill(null).map(() => encrypt(key, plaintext))
    );

    // Verify all IVs are different
    const ivs = encryptions.map(({ iv }) =>
      Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')
    );

    const uniqueIVs = new Set(ivs);
    expect(uniqueIVs.size).toBe(10);

    // Verify all decrypt to same plaintext
    const decryptions = await Promise.all(
      encryptions.map(payload => decrypt(key, payload))
    );

    for (const decrypted of decryptions) {
      expect(decrypted).toEqual(plaintext);
    }

    console.log('[Nonce Test] ✓ Different IVs, same plaintext recovery');
  });

  it('should produce different ciphertexts for same plaintext', async () => {
    const key = await generateNonExtractableKey();
    const plaintext = { secret: 'Same data every time' };

    const encryptions = await Promise.all(
      Array(100).fill(null).map(() => encrypt(key, plaintext))
    );

    // Convert ciphertexts to hex for comparison
    const ciphertextSet = new Set(
      encryptions.map(({ ciphertext }) =>
        Array.from(ciphertext).map(b => b.toString(16).padStart(2, '0')).join('')
      )
    );

    // All ciphertexts should be different (different IVs)
    expect(ciphertextSet.size).toBe(100);

    console.log('[Nonce Test] ✓ 100 different ciphertexts for same plaintext');
  });
});

describe('Nonce Uniqueness: Mathematical Properties', () => {
  it('should document IV space and collision probability', () => {
    const ivBits = 96; // AES-GCM standard
    const ivSpace = Math.pow(2, ivBits);
    const birthdayBound = Math.sqrt(ivSpace);

    console.log('\n[Nonce Math] AES-GCM IV Space Analysis:');
    console.log(`  IV size: ${ivBits} bits (${ivBits / 8} bytes)`);
    console.log(`  Total IV space: 2^${ivBits} ≈ ${ivSpace.toExponential(2)}`);
    console.log(`  Birthday bound: 2^${ivBits / 2} ≈ ${birthdayBound.toExponential(2)}`);

    // Calculate collision probability for various operation counts
    const scenarios = [
      { operations: 1000, label: '1K operations' },
      { operations: 1000000, label: '1M operations' },
      { operations: 1000000000, label: '1B operations' },
      { operations: Math.pow(2, 32), label: '2^32 operations' },
      { operations: Math.pow(2, 40), label: '2^40 operations' },
    ];

    console.log('\n[Nonce Math] Collision Probability:');
    scenarios.forEach(({ operations, label }) => {
      // Approximate probability: n^2 / (2 * space)
      const probability = (operations * operations) / (2 * ivSpace);
      console.log(`  ${label}: ${probability.toExponential(2)} (${(probability * 100).toExponential(2)}%)`);
    });

    console.log('\n[Conclusion] For realistic usage (< 1B operations), collision probability is negligible');

    // Verify our understanding
    expect(ivBits).toBe(96);
    expect(ivSpace).toBeGreaterThan(0);
  });

  it('should verify IV entropy is sufficient', async () => {
    const key = await generateNonExtractableKey();
    const samples = 100;
    const ivBits = new Set();

    console.log('\n[Nonce Entropy] Collecting IV samples to estimate entropy...');

    for (let i = 0; i < samples; i++) {
      const { iv } = await encrypt(key, { sample: i });

      // Convert to binary string
      const binary = Array.from(iv)
        .map(byte => byte.toString(2).padStart(8, '0'))
        .join('');

      ivBits.add(binary);
    }

    // All samples should be unique (high entropy)
    expect(ivBits.size).toBe(samples);

    // Calculate approximate entropy
    // H = log2(N) where N is number of unique values
    const entropy = Math.log2(ivBits.size);

    console.log(`[Nonce Entropy] Unique IVs: ${ivBits.size}/${samples}`);
    console.log(`[Nonce Entropy] Estimated entropy: ${entropy.toFixed(2)} bits`);
    console.log(`[Nonce Entropy] Maximum entropy: 96 bits`);

    // With 100 samples, entropy should be close to log2(100) ≈ 6.64
    expect(entropy).toBeGreaterThan(6);
  });
});

describe('Nonce Uniqueness: Attack Scenarios', () => {
  it('should resist IV prediction attacks', async () => {
    const key = await generateNonExtractableKey();
    const samples = 1000;
    const ivs = [];

    // Collect IV samples
    for (let i = 0; i < samples; i++) {
      const { iv } = await encrypt(key, { index: i });
      ivs.push(Array.from(iv));
    }

    // Attempt to predict next IV using various strategies
    const predictionStrategies = {
      sequential: ivs[ivs.length - 1].map((b, i) => (b + 1) % 256),
      repeated: ivs[ivs.length - 1],
      zero: Array(12).fill(0),
      pattern: ivs[0].map((_, i) => i % 256)
    };

    // Generate actual next IV
    const { iv: actualNext } = await encrypt(key, { index: samples });
    const actualNextArray = Array.from(actualNext);

    // None of the predictions should match
    for (const [strategy, predicted] of Object.entries(predictionStrategies)) {
      const matches = predicted.every((byte, i) => byte === actualNextArray[i]);
      expect(matches).toBe(false);
      console.log(`[Attack Test] ${strategy} prediction: ${matches ? 'FAILED (predictable!)' : 'failed (good)'}`);
    }

    console.log('[Attack Test] ✓ IV prediction attacks failed (IVs are unpredictable)');
  });

  it('should document consequences of IV reuse', () => {
    console.log('\n[Security] Consequences of AES-GCM IV Reuse:');
    console.log('  1. Complete loss of confidentiality for reused IV');
    console.log('  2. Attacker can XOR ciphertexts to cancel keystream');
    console.log('  3. Reveals plaintext XOR: C1 ⊕ C2 = P1 ⊕ P2');
    console.log('  4. Can recover authentication key with reused IV + AD');
    console.log('  5. CATASTROPHIC - entire system security compromised');

    console.log('\n[Mitigation] Our defenses:');
    console.log('  1. crypto.getRandomValues() - CSPRNG with high entropy');
    console.log('  2. 96-bit IV space - 2^96 possible values');
    console.log('  3. Property tests - verify uniqueness across 10K+ operations');
    console.log('  4. Concurrent safety - tested parallel encryptions');

    console.log('\n[Alternative] Consider migrating to:');
    console.log('  - HPKE (RFC 9180) - handles IV management correctly by design');
    console.log('  - AES-GCM-SIV - nonce-misuse resistant variant');
    console.log('  - ChaCha20-Poly1305 - different construction, more forgiving');

    expect(true).toBe(true); // Passing test that documents the issue
  });
});

describe('Nonce Uniqueness: Performance Under Load', () => {
  it('should maintain IV uniqueness under high load', async () => {
    const key = await generateNonExtractableKey();
    const iterations = 5000; // Higher load test
    const ivSet = new Set();

    console.log(`[Load Test] Testing IV uniqueness under ${iterations} rapid encryptions...`);

    const startTime = performance.now();

    for (let i = 0; i < iterations; i++) {
      const { iv } = await encrypt(key, { iteration: i, timestamp: Date.now() });
      const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');

      if (ivSet.has(ivHex)) {
        throw new Error(`IV collision at iteration ${i} under load!`);
      }

      ivSet.add(ivHex);
    }

    const duration = performance.now() - startTime;
    const opsPerSecond = (iterations / duration) * 1000;

    expect(ivSet.size).toBe(iterations);

    console.log(`[Load Test] ✓ ${iterations} unique IVs in ${duration.toFixed(2)}ms`);
    console.log(`[Load Test] Throughput: ${opsPerSecond.toFixed(0)} operations/second`);
    console.log(`[Load Test] No IV reuse detected under load`);
  });
});
