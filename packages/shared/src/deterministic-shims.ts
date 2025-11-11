// @ts-nocheck - This file intentionally manipulates prototypes and uses low-level operations for determinism
/**
 * Deterministic Realm Shims
 *
 * Hardens the JavaScript realm for deterministic execution by:
 * 1. Replacing non-deterministic sources (Date.now, Math.random)
 * 2. Freezing primordials to prevent prototype poisoning
 * 3. Removing access to timing APIs
 *
 * Based on security review recommendations and SES principles.
 *
 * Usage:
 *   import { hardenRealm } from './deterministic-shims.js';
 *   hardenRealm({ seed: 0x12345678 }); // Before loading guest code
 *
 * @see https://github.com/endojs/endo/tree/master/packages/ses
 */

/**
 * XORShift32 PRNG for deterministic Math.random()
 *
 * Fast, simple, and deterministic pseudorandom number generator.
 * Given the same seed, produces the same sequence.
 *
 * @param {number} seed - 32-bit seed (must be non-zero)
 * @returns {function(): number} Deterministic random function
 */
function createDeterministicRandom(seed) {
  let state = (seed >>> 0) || 0x9e3779b1; // Default seed if zero

  if (state === 0) {
    throw new Error('XORShift32 seed must be non-zero');
  }

  return function random() {
    // XORShift32 algorithm
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;

    // Convert to [0, 1) range
    return ((state >>> 0) & 0x7fffffff) / 0x80000000;
  };
}

/**
 * Create deterministic Date implementation
 *
 * Fixes Date.now() to a constant value and ensures Date() constructor
 * returns deterministic values.
 *
 * @param {number} fixedTime - Fixed timestamp (milliseconds since epoch)
 * @returns {Object} Deterministic Date shims
 */
function createDeterministicDate(fixedTime) {
  const OriginalDate = Date;

  // Fixed Date.now()
  const deterministicNow = () => fixedTime;

  // Deterministic Date constructor
  // When called with no args, should return fixed time
  const DeterministicDate = new Proxy(OriginalDate, {
    construct(Target, args) {
      if (args.length === 0) {
        // new Date() with no args → use fixed time
        return new Target(fixedTime);
      }
      // new Date(args) → pass through to original
      return new Target(...args);
    },

    apply(Target, thisArg, args) {
      if (args.length === 0) {
        // Date() with no args → return string for fixed time
        return new Target(fixedTime).toString();
      }
      return Reflect.apply(Target, thisArg, args);
    }
  });

  // Copy static methods
  Object.setPrototypeOf(DeterministicDate, OriginalDate);
  DeterministicDate.prototype = OriginalDate.prototype;
  DeterministicDate.now = deterministicNow;
  DeterministicDate.UTC = OriginalDate.UTC;
  DeterministicDate.parse = OriginalDate.parse;

  return {
    Date: DeterministicDate,
    now: deterministicNow
  };
}

/**
 * Freeze primordials to prevent prototype poisoning
 *
 * Freezes built-in constructors and their prototypes so guest code
 * cannot modify them (e.g., Object.prototype.toString).
 *
 * This is a subset of what SES does - for full hardening, use SES.
 */
function freezePrimordials() {
  const { freeze } = Object;

  const primordials = [
    Object,
    Array,
    Function,
    Number,
    String,
    Boolean,
    RegExp,
    Map,
    Set,
    WeakMap,
    WeakSet,
    Error,
    Promise,
    Symbol,
    // Math and JSON are already immutable objects
  ];

  for (const ctor of primordials) {
    try {
      freeze(ctor);
      if (ctor.prototype) {
        freeze(ctor.prototype);
      }
    } catch (e) {
      // Some environments may not allow freezing
      console.warn(`[Determinism] Could not freeze ${ctor.name}:`, e.message);
    }
  }

  // Freeze Math and JSON
  freeze(Math);
  freeze(JSON);

  console.log('[Determinism] Primordials frozen');
}

/**
 * Remove non-deterministic global APIs
 *
 * Removes or neuters APIs that could introduce non-determinism:
 * - performance.now() (high-resolution timer)
 * - setTimeout/setInterval (timing-based)
 * - requestAnimationFrame (browser-specific)
 *
 * For QuickJS in worker, most of these don't exist, but we remove them
 * defensively in case running in a different environment.
 */
function removeNonDeterministicAPIs() {
  const globalObj = typeof globalThis !== 'undefined' ? globalThis : self;

  // Remove timing APIs
  const toRemove = [
    'setTimeout',
    'setInterval',
    'setImmediate',
    'requestAnimationFrame',
    'requestIdleCallback',
  ];

  for (const api of toRemove) {
    if (api in globalObj) {
      delete globalObj[api];
      console.log(`[Determinism] Removed ${api}`);
    }
  }

  // Neuter performance.now() if it exists
  if (globalObj.performance && globalObj.performance.now) {
    const fixedPerformanceTime = 0;
    globalObj.performance.now = () => fixedPerformanceTime;
    console.log('[Determinism] Neutered performance.now()');
  }
}

/**
 * Harden the JavaScript realm for deterministic execution
 *
 * This function should be called BEFORE any guest code is loaded.
 *
 * @param {Object} options - Configuration options
 * @param {number} [options.seed=0x9e3779b1] - Seed for Math.random()
 * @param {number} [options.fixedTime=1700000000000] - Fixed timestamp for Date.now()
 * @param {boolean} [options.freezePrimordials=true] - Whether to freeze built-ins
 * @param {boolean} [options.removeTimers=true] - Whether to remove timing APIs
 * @returns {Object} Information about hardening applied
 */
export function hardenRealm(options = {}) {
  const {
    seed = 0x9e3779b1,
    fixedTime = 1700000000000, // ~2023-11-15
    freezePrimordials: shouldFreeze = true,
    removeTimers = true,
  } = options;

  const globalObj = typeof globalThis !== 'undefined' ? globalThis : self;
  const results = {
    deterministicRandom: false,
    deterministicDate: false,
    frozenPrimordials: false,
    removedAPIs: [],
  };

  console.log('[Determinism] Hardening realm...');

  // 1. Replace Math.random with deterministic version
  try {
    const random = createDeterministicRandom(seed);
    globalObj.Math.random = random;
    results.deterministicRandom = true;
    console.log(`[Determinism] Math.random seeded with 0x${seed.toString(16)}`);
  } catch (e) {
    console.warn('[Determinism] Could not replace Math.random:', e.message);
  }

  // 2. Replace Date with deterministic version
  try {
    const { Date: DeterministicDate, now } = createDeterministicDate(fixedTime);
    globalObj.Date = DeterministicDate;
    results.deterministicDate = true;
    console.log(`[Determinism] Date.now() fixed to ${fixedTime}`);
  } catch (e) {
    console.warn('[Determinism] Could not replace Date:', e.message);
  }

  // 3. Freeze primordials
  if (shouldFreeze) {
    try {
      freezePrimordials();
      results.frozenPrimordials = true;
    } catch (e) {
      console.warn('[Determinism] Could not freeze primordials:', e.message);
    }
  }

  // 4. Remove non-deterministic APIs
  if (removeTimers) {
    try {
      removeNonDeterministicAPIs();
      results.removedAPIs = ['setTimeout', 'setInterval', 'performance.now'];
    } catch (e) {
      console.warn('[Determinism] Could not remove APIs:', e.message);
    }
  }

  console.log('[Determinism] Realm hardening complete:', results);
  return results;
}

/**
 * Derive deterministic seed from input data
 *
 * For test cases or reproducible sessions, derive a seed from input data.
 *
 * @param {string} data - Input data (e.g., session ID, test name)
 * @returns {Promise<number>} 32-bit seed
 */
export async function deriveSeedFromData(data) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  const hashArray = new Uint8Array(hashBuffer);

  // Take first 4 bytes as seed
  const dataView = new DataView(hashArray.buffer);
  const seed = dataView.getUint32(0, false); // big-endian

  return seed || 0x9e3779b1; // Fallback if seed is zero
}

/**
 * Verify determinism by running function twice
 *
 * Useful for testing that a function produces deterministic output.
 *
 * @param {Function} fn - Function to test (should be pure)
 * @param {Array} args - Arguments to pass
 * @returns {Object} Results from both runs
 */
export async function verifyDeterminism(fn, args = []) {
  const seed = 0x12345678;

  // First run
  hardenRealm({ seed });
  const result1 = await fn(...args);

  // Second run (re-harden with same seed)
  hardenRealm({ seed });
  const result2 = await fn(...args);

  const isDeterministic = JSON.stringify(result1) === JSON.stringify(result2);

  return {
    isDeterministic,
    result1,
    result2,
    message: isDeterministic
      ? 'Function is deterministic'
      : 'Function is NOT deterministic - results differ',
  };
}

/**
 * Create a minimal "compartment" for running guest code
 *
 * This is a simplified version of SES Compartment.
 * For production, consider using the full SES implementation.
 *
 * @param {Object} endowments - Global variables to provide to guest code
 * @returns {Object} Compartment API
 */
export function createCompartment(endowments = {}) {
  // Create a fresh global scope
  const compartmentGlobal = Object.create(null);

  // Add safe built-ins
  compartmentGlobal.Object = Object;
  compartmentGlobal.Array = Array;
  compartmentGlobal.String = String;
  compartmentGlobal.Number = Number;
  compartmentGlobal.Boolean = Boolean;
  compartmentGlobal.Math = Math;
  compartmentGlobal.JSON = JSON;
  compartmentGlobal.console = console;

  // Add endowments
  Object.assign(compartmentGlobal, endowments);

  return {
    evaluate(code) {
      // Create an indirect eval in the compartment scope
      // This is simplified - real SES uses more sophisticated isolation
      const fn = new Function(
        ...Object.keys(compartmentGlobal),
        `'use strict'; return (${code})`
      );

      return fn(...Object.values(compartmentGlobal));
    },

    global: compartmentGlobal,
  };
}

// Export for testing
export const __test__ = {
  createDeterministicRandom,
  createDeterministicDate,
  freezePrimordials,
};
