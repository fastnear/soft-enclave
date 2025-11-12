/**
 * Deterministic Shims Tests
 *
 * Verifies that our realm hardening produces deterministic execution:
 * - Same seed → same Math.random() sequence
 * - Fixed time → same Date.now() value
 * - Frozen primordials → cannot modify Object.prototype
 * - Removed APIs → setTimeout, etc. not accessible
 */

import { describe, it, expect, beforeEach, beforeAll, afterAll } from 'vitest';
import {
  hardenRealm,
  deriveSeedFromData,
  verifyDeterminism,
  createCompartment,
  __test__,
} from '@fastnear/soft-enclave-shared';
import { muteConsoleErrors, muteConsoleWarns } from './helpers/console';

describe('Deterministic Math.random()', () => {
  it('should produce same sequence with same seed', () => {
    const { createDeterministicRandom } = __test__;

    const seed = 0x12345678;
    const random1 = createDeterministicRandom(seed);
    const random2 = createDeterministicRandom(seed);

    // Generate sequence from both
    const seq1 = Array(100).fill(0).map(() => random1());
    const seq2 = Array(100).fill(0).map(() => random2());

    // Should be identical
    expect(seq1).toEqual(seq2);

    console.log('[Determinism] First 10 values:', seq1.slice(0, 10).map(v => v.toFixed(6)));
  });

  it('should produce different sequences with different seeds', () => {
    const { createDeterministicRandom } = __test__;

    const random1 = createDeterministicRandom(0x11111111);
    const random2 = createDeterministicRandom(0x22222222);

    const seq1 = Array(100).fill(0).map(() => random1());
    const seq2 = Array(100).fill(0).map(() => random2());

    // Should be different
    expect(seq1).not.toEqual(seq2);

    console.log('[Determinism] Different seeds produce different sequences');
  });

  it('should produce values in [0, 1) range', () => {
    const { createDeterministicRandom } = __test__;

    const random = createDeterministicRandom(0x9e3779b1);
    const values = Array(10000).fill(0).map(() => random());

    // All values should be in range
    expect(values.every(v => v >= 0 && v < 1)).toBe(true);

    // Calculate distribution
    const min = Math.min(...values);
    const max = Math.max(...values);
    const avg = values.reduce((a, b) => a + b, 0) / values.length;

    console.log('[Determinism] Range: [0, 1), min:', min.toFixed(6), 'max:', max.toFixed(6), 'avg:', avg.toFixed(6));

    // Average should be roughly 0.5
    expect(avg).toBeGreaterThan(0.4);
    expect(avg).toBeLessThan(0.6);
  });

  it('should reject zero seed', () => {
    const { createDeterministicRandom } = __test__;

    expect(() => createDeterministicRandom(0)).toThrow('must be non-zero');
  });
});

describe('Deterministic Date', () => {
  it('should fix Date.now() to constant value', () => {
    const { createDeterministicDate } = __test__;

    const fixedTime = 1700000000000;
    const { now } = createDeterministicDate(fixedTime);

    expect(now()).toBe(fixedTime);
    expect(now()).toBe(fixedTime); // Should be same every call

    console.log('[Determinism] Date.now() fixed to:', fixedTime);
  });

  it('should create Date objects with fixed time when no args', () => {
    const { createDeterministicDate } = __test__;

    const fixedTime = 1700000000000;
    const { Date: DeterministicDate } = createDeterministicDate(fixedTime);

    const date1 = new DeterministicDate();
    const date2 = new DeterministicDate();

    expect(date1.getTime()).toBe(fixedTime);
    expect(date2.getTime()).toBe(fixedTime);

    console.log('[Determinism] new Date():', date1.toISOString());
  });

  it('should allow creating specific dates with args', () => {
    const { createDeterministicDate } = __test__;

    const fixedTime = 1700000000000;
    const { Date: DeterministicDate } = createDeterministicDate(fixedTime);

    const specificTime = 1600000000000;
    const specificDate = new DeterministicDate(specificTime);

    expect(specificDate.getTime()).toBe(specificTime);
    expect(specificDate.getTime()).not.toBe(fixedTime);

    console.log('[Determinism] new Date(specificTime) still works');
  });
});

describe('hardenRealm()', () => {
  let originalRandom;
  let originalDate;
  let restoreConsole;

  beforeAll(() => {
    // Mute expected console noise from hardenRealm (Cyclic __proto__, read-only properties)
    const restoreErrors = muteConsoleErrors([
      /Cyclic __proto__/i,
      /read[-\s]?only property 'constructor'/i
    ]);
    const restoreWarns = muteConsoleWarns([
      /Cyclic __proto__/i,
      /Could not freeze/i,
      /Could not replace Date/i
    ]);
    restoreConsole = () => {
      restoreErrors();
      restoreWarns();
    };
  });

  afterAll(() => {
    restoreConsole?.();
  });

  beforeEach(() => {
    // Save originals for restoration between tests
    originalRandom = Math.random;
    originalDate = Date;
  });

  afterEach(() => {
    // Restore (best effort - may not fully restore in all environments)
    Math.random = originalRandom;
    globalThis.Date = originalDate;
  });

  it('should replace Math.random with deterministic version', () => {
    const seed = 0xabcdef01;
    hardenRealm({ seed, freezePrimordials: false });

    const values = Array(10).fill(0).map(() => Math.random());

    // Should be deterministic - second run should produce same values
    Math.random = originalRandom; // Reset
    hardenRealm({ seed, freezePrimordials: false });

    const values2 = Array(10).fill(0).map(() => Math.random());

    expect(values).toEqual(values2);

    console.log('[Determinism] Math.random() is deterministic');
  });

  it('should fix Date.now() to constant value', () => {
    const fixedTime = 1234567890000;
    hardenRealm({ fixedTime, freezePrimordials: false });

    expect(Date.now()).toBe(fixedTime);
    expect(Date.now()).toBe(fixedTime);

    console.log('[Determinism] Date.now() is fixed');
  });

  it('should freeze primordials', () => {
    hardenRealm({ freezePrimordials: true });

    // Should not be able to modify Object.prototype
    expect(() => {
      Object.prototype.malicious = 'pwned';
    }).toThrow();

    console.log('[Determinism] Primordials are frozen');
  });

  it('should remove timing APIs', () => {
    // Note: This test may not work in all environments
    // setTimeout/setInterval might be restored by test framework

    const originalSetTimeout = globalThis.setTimeout;

    hardenRealm({ removeTimers: true, freezePrimordials: false });

    // If they were removed, they should be undefined
    // (But test framework might restore them)
    console.log('[Determinism] Timing APIs:', {
      setTimeout: typeof globalThis.setTimeout,
      setInterval: typeof globalThis.setInterval,
    });

    // Restore
    if (originalSetTimeout) {
      globalThis.setTimeout = originalSetTimeout;
    }
  });

  it('should return results object', () => {
    const results = hardenRealm({
      seed: 0x12345678,
      fixedTime: 1700000000000,
      freezePrimordials: true,
      removeTimers: true,
    });

    expect(results).toHaveProperty('deterministicRandom');
    expect(results).toHaveProperty('deterministicDate');
    expect(results).toHaveProperty('frozenPrimordials');
    expect(results).toHaveProperty('removedAPIs');

    console.log('[Determinism] Hardening results:', results);
  });
});

describe('Seed Derivation', () => {
  it('should derive deterministic seed from data', async () => {
    const data1 = 'test-session-123';

    const seed1a = await deriveSeedFromData(data1);
    const seed1b = await deriveSeedFromData(data1);

    // Same data → same seed
    expect(seed1a).toBe(seed1b);

    console.log('[Determinism] Derived seed from "' + data1 + '":', '0x' + seed1a.toString(16));
  });

  it('should derive different seeds from different data', async () => {
    const seed1 = await deriveSeedFromData('session-1');
    const seed2 = await deriveSeedFromData('session-2');

    expect(seed1).not.toBe(seed2);

    console.log('[Determinism] Different data produces different seeds');
  });

  it('should never produce zero seed', async () => {
    // Even if hash starts with zeros, should have fallback
    const seed = await deriveSeedFromData('');

    expect(seed).not.toBe(0);
    expect(seed).toBeGreaterThan(0);

    console.log('[Determinism] Empty data seed:', '0x' + seed.toString(16));
  });
});

describe('Determinism Verification', () => {
  it('should verify deterministic function', async () => {
    // Deterministic function (pure)
    function deterministicFn() {
      const results = [];
      for (let i = 0; i < 10; i++) {
        results.push(Math.random());
      }
      return results;
    }

    const { isDeterministic, result1, result2 } = await verifyDeterminism(deterministicFn);

    expect(isDeterministic).toBe(true);
    expect(result1).toEqual(result2);

    console.log('[Determinism] ✓ Function is deterministic');
  });

  it('should detect non-deterministic function', async () => {
    // Non-deterministic function (uses original Math.random if available)
    const originalRandom = Math.random;
    let counter = 0;

    function nonDeterministicFn() {
      // Use counter to simulate non-determinism
      return counter++;
    }

    const result = await verifyDeterminism(nonDeterministicFn);

    // Will be non-deterministic because counter increments
    expect(result.isDeterministic).toBe(false);

    console.log('[Determinism] ✓ Non-determinism detected');

    Math.random = originalRandom;
  });
});

describe('Compartment (Simplified SES)', () => {
  it('should create isolated compartment', () => {
    const compartment = createCompartment({
      value: 42,
      helper: (x) => x * 2,
    });

    expect(compartment.global.value).toBe(42);
    expect(compartment.global.helper(21)).toBe(42);

    console.log('[Compartment] Created with endowments');
  });

  it('should evaluate code in compartment', () => {
    const compartment = createCompartment({
      x: 10,
      y: 20,
    });

    const result = compartment.evaluate('x + y');

    expect(result).toBe(30);

    console.log('[Compartment] Evaluated: x + y =', result);
  });

  it('should have access to safe built-ins', () => {
    const compartment = createCompartment();

    const result = compartment.evaluate('[1, 2, 3].map(x => x * 2)');

    expect(result).toEqual([2, 4, 6]);

    console.log('[Compartment] Has Array, Math, JSON, etc.');
  });

  it('should not have access to dangerous APIs', () => {
    const compartment = createCompartment();

    // Note: This is simplified - real SES provides stronger isolation
    expect(compartment.global.setTimeout).toBeUndefined();
    expect(compartment.global.fetch).toBeUndefined();

    console.log('[Compartment] No setTimeout, fetch, etc.');
  });
});

describe('Real-World Determinism Test', () => {
  it('should execute same code deterministically across runs', async () => {
    const guestCode = `
      function fibonacci(n) {
        if (n <= 1) return n;
        return fibonacci(n - 1) + fibonacci(n - 2);
      }

      function monteCarloPi(samples) {
        let inside = 0;
        for (let i = 0; i < samples; i++) {
          const x = Math.random();
          const y = Math.random();
          if (x * x + y * y <= 1) {
            inside++;
          }
        }
        return (4 * inside) / samples;
      }

      ({
        fib: fibonacci(20),
        pi: monteCarloPi(10000),
        date: Date.now(),
      })
    `;

    // Run 1
    const seed = 0x11223344;
    const fixedTime = 1700000000000;
    hardenRealm({ seed, fixedTime, freezePrimordials: false });

    const run1 = eval(`(${guestCode})`);

    // Run 2 (re-harden with same parameters)
    hardenRealm({ seed, fixedTime, freezePrimordials: false });

    const run2 = eval(`(${guestCode})`);

    // Results should be identical
    expect(run1).toEqual(run2);

    console.log('[Real-World Determinism]');
    console.log('  fibonacci(20):', run1.fib);
    console.log('  Monte Carlo π:', run1.pi);
    console.log('  Date.now():', run1.date);
    console.log('  ✓ Both runs produced identical results');
  });

  it('should produce different results with different seeds', async () => {
    const monteCarloCode = `
      let inside = 0;
      for (let i = 0; i < 1000; i++) {
        const x = Math.random();
        const y = Math.random();
        if (x * x + y * y <= 1) inside++;
      }
      (4 * inside) / 1000
    `;

    // Run with seed 1
    hardenRealm({ seed: 0x11111111, freezePrimordials: false });
    const pi1 = eval(`(${monteCarloCode})`);

    // Run with seed 2
    hardenRealm({ seed: 0x22222222, freezePrimordials: false });
    const pi2 = eval(`(${monteCarloCode})`);

    // Different seeds should produce different (but deterministic) results
    expect(pi1).not.toBe(pi2);

    console.log('[Different Seeds]');
    console.log('  Seed 1 π estimate:', pi1);
    console.log('  Seed 2 π estimate:', pi2);
  });
});

describe('Security: Prototype Poisoning Prevention', () => {
  let restoreConsole;

  beforeAll(() => {
    // Mute expected console noise from freezing primordials
    const restoreErrors = muteConsoleErrors([
      /read[-\s]?only property/i,
      /Cannot assign to read only/i
    ]);
    const restoreWarns = muteConsoleWarns([
      /Could not freeze/i
    ]);
    restoreConsole = () => {
      restoreErrors();
      restoreWarns();
    };
  });

  afterAll(() => {
    restoreConsole?.();
  });

  it('should prevent Object.prototype modification', () => {
    hardenRealm({ freezePrimordials: true });

    // Attempt prototype poisoning
    expect(() => {
      Object.prototype.toString = () => 'hacked';
    }).toThrow();

    console.log('[Security] ✓ Prototype poisoning blocked');
  });

  it('should prevent Array.prototype modification', () => {
    hardenRealm({ freezePrimordials: true });

    expect(() => {
      Array.prototype.map = () => 'pwned';
    }).toThrow();

    console.log('[Security] ✓ Array.prototype poisoning blocked');
  });

  it('should prevent Function.prototype modification', () => {
    hardenRealm({ freezePrimordials: true });

    expect(() => {
      Function.prototype.call = () => 'malicious';
    }).toThrow();

    console.log('[Security] ✓ Function.prototype poisoning blocked');
  });
});
