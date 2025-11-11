/**
 * Deterministic Prelude
 *
 * Hardens the JavaScript environment for deterministic, reproducible execution.
 * Ported from near-outlayer's quickjs-enclave.ts implementation.
 *
 * This prelude:
 * 1. Replaces Math.random() with deterministic LCG PRNG
 * 2. Freezes Date.now() to return 0
 * 3. Disables eval()
 * 4. Removes setTimeout, setInterval, setImmediate
 * 5. Freezes Object/Array/Function prototypes
 *
 * Usage:
 * ```javascript
 * import { createDeterministicPrelude } from './near/deterministic-prelude.js';
 *
 * const prelude = createDeterministicPrelude('my-seed-12345');
 * await enclave.execute(prelude + contractCode);
 * ```
 */

/**
 * Linear Congruential Generator (LCG) for deterministic random numbers
 *
 * Uses the same algorithm as glibc's rand():
 * - Multiplier: 6364136223846793005
 * - Increment: 1442695040888963407
 * - Modulus: 2^64 (implicit via BigInt overflow)
 *
 * This ensures:
 * - Same seed → same sequence
 * - Fast execution
 * - Sufficient randomness for contracts
 *
 * @param {string} seed - Seed string (e.g., block hash + account ID)
 * @returns {Function} Deterministic random function [0, 1)
 */
function createLCGRandom(seed) {
  // Hash seed into 64-bit state
  let state = 0n;
  for (let i = 0; i < seed.length; i++) {
    state = (state * 131n + BigInt(seed.charCodeAt(i))) & 0xffffffffffffffffn;
  }

  // LCG constants (same as glibc)
  const MULTIPLIER = 6364136223846793005n;
  const INCREMENT = 1442695040888963407n;
  const MASK = 0xffffffffffffffffn;

  return function random() {
    // Next state
    state = (MULTIPLIER * state + INCREMENT) & MASK;

    // Extract 48 bits and normalize to [0, 1)
    const bits = state & 0x3fffffffffffn; // 46 bits
    return Number(bits) / Number(0x400000000000n);
  };
}

/**
 * Create deterministic prelude code
 *
 * @param {string} seed - Seed for random number generator
 * @param {object} options - Configuration options
 * @param {boolean} options.freezePrototypes - Freeze built-in prototypes (default: true)
 * @param {boolean} options.disableEval - Disable eval() (default: true)
 * @param {boolean} options.disableTimers - Remove setTimeout/setInterval (default: true)
 * @param {boolean} options.freezeDate - Make Date.now() return 0 (default: true)
 * @returns {string} JavaScript prelude code
 */
export function createDeterministicPrelude(seed = 'default-seed', options = {}) {
  const {
    freezePrototypes = true,
    disableEval = true,
    disableTimers = true,
    freezeDate = true
  } = options;

  // Convert seed to safe string literal
  const safeSeed = seed.replace(/\\/g, '\\\\').replace(/'/g, "\\'");

  return `
// Deterministic Prelude
// =====================
// Hardens environment for reproducible execution

(function __harden__() {
  'use strict';

  const seed = '${safeSeed}';

  // 1. Deterministic Math.random() using LCG
  // ========================================
  let state = 0n;
  for (let i = 0; i < seed.length; i++) {
    state = (state * 131n + BigInt(seed.charCodeAt(i))) & 0xffffffffffffffffn;
  }

  const MULTIPLIER = 6364136223846793005n;
  const INCREMENT = 1442695040888963407n;
  const MASK = 0xffffffffffffffffn;

  Math.random = function random() {
    state = (MULTIPLIER * state + INCREMENT) & MASK;
    const bits = state & 0x3fffffffffffn;
    return Number(bits) / Number(0x400000000000n);
  };

  ${freezeDate ? `
  // 2. Freeze Date.now() to 0
  // ==========================
  const OriginalDate = Date;
  globalThis.Date = class Date extends OriginalDate {
    constructor(...args) {
      if (args.length === 0) {
        // new Date() returns epoch
        super(0);
      } else {
        super(...args);
      }
    }

    static now() {
      return 0;
    }
  };

  // Preserve other Date static methods
  Object.setPrototypeOf(globalThis.Date, OriginalDate);
  Object.setPrototypeOf(globalThis.Date.prototype, OriginalDate.prototype);
  ` : ''}

  ${disableEval ? `
  // 3. Disable eval()
  // =================
  globalThis.eval = function eval() {
    throw new Error('eval() is disabled for security');
  };

  // Also disable Function constructor
  const OriginalFunction = Function;
  globalThis.Function = function Function() {
    throw new Error('Function constructor is disabled for security');
  };
  ` : ''}

  ${disableTimers ? `
  // 4. Remove timers (non-deterministic)
  // ====================================
  globalThis.setTimeout = undefined;
  globalThis.setInterval = undefined;
  globalThis.setImmediate = undefined;
  globalThis.clearTimeout = undefined;
  globalThis.clearInterval = undefined;
  globalThis.clearImmediate = undefined;
  ` : ''}

  ${freezePrototypes ? `
  // 5. Freeze built-in prototypes
  // ==============================
  // Prevents contracts from modifying shared prototypes

  try {
    Object.freeze(Object.prototype);
    Object.freeze(Array.prototype);
    Object.freeze(String.prototype);
    Object.freeze(Number.prototype);
    Object.freeze(Boolean.prototype);
    Object.freeze(Function.prototype);
    Object.freeze(Math);
    Object.freeze(JSON);
  } catch (e) {
    // In some environments, freezing may fail
    // Continue anyway - best effort hardening
  }
  ` : ''}

  // Lock down globalThis (best effort)
  try {
    // Prevent adding new globals
    Object.preventExtensions(globalThis);
  } catch (e) {
    // May fail in some environments
  }
})();
`;
}

/**
 * Wrap contract code with deterministic prelude
 *
 * @param {string} contractCode - Contract code
 * @param {string} seed - Deterministic seed
 * @param {object} options - Prelude options
 * @returns {string} Hardened contract code
 */
export function wrapWithPrelude(contractCode, seed = 'default-seed', options = {}) {
  const prelude = createDeterministicPrelude(seed, options);
  return prelude + '\n\n' + contractCode;
}

/**
 * Execute contract with deterministic prelude
 *
 * @param {object} enclave - Enclave instance
 * @param {string} contractCode - Contract code
 * @param {string} seed - Seed for determinism
 * @param {object} context - Execution context
 * @param {object} options - Prelude options
 * @returns {Promise<object>} Execution result
 */
export async function executeWithPrelude(
  enclave,
  contractCode,
  seed = 'default-seed',
  context = {},
  options = {}
) {
  const wrappedCode = wrapWithPrelude(contractCode, seed, options);
  return await enclave.execute(wrappedCode, context);
}

/**
 * Create NEAR-compatible execution environment
 *
 * Combines deterministic prelude with NEAR storage shim
 *
 * @param {string} seed - Deterministic seed
 * @param {object} state - NEAR storage state
 * @param {object} options - Configuration
 * @returns {string} Complete execution environment
 */
export function createNEAREnvironment(seed, state = {}, options = {}) {
  // Import is dynamic, so we generate the code directly
  const prelude = createDeterministicPrelude(seed, options);

  const stateJson = JSON.stringify(state);

  const nearShim = `
// NEAR Storage Shim
const __STATE__ = ${stateJson};
const __LOGS__ = [];

const near = Object.freeze({
  storageRead: (key) => {
    const value = __STATE__[key];
    __LOGS__.push(\`[storage] Read "\${key}": \${JSON.stringify(value)}\`);
    return value;
  },
  storageWrite: (key, value) => {
    __STATE__[key] = value;
    __LOGS__.push(\`[storage] Write "\${key}": \${JSON.stringify(value)}\`);
  },
  log: (...args) => {
    const message = args.map(a =>
      typeof a === 'string' ? a : JSON.stringify(a)
    ).join(' ');
    __LOGS__.push(\`[contract] \${message}\`);
  }
});

globalThis.near = near;
`;

  return prelude + '\n\n' + nearShim;
}

/**
 * Example usage:
 *
 * ```javascript
 * import { executeWithPrelude, createNEAREnvironment } from './near/deterministic-prelude.js';
 *
 * // Simple deterministic execution
 * const result = await executeWithPrelude(
 *   enclave,
 *   `Math.random() * 100`,
 *   'block-hash-123'
 * );
 *
 * // Full NEAR environment
 * const env = createNEAREnvironment('block-hash-123', { count: 0 });
 * const contractCode = `
 *   const count = near.storageRead('count') || 0;
 *   near.storageWrite('count', count + 1);
 *   near.log('Count:', count + 1);
 *   const randomValue = Math.random(); // Deterministic!
 *   ({ result: count + 1, random: randomValue, __STATE__, __LOGS__ });
 * `;
 *
 * const execution = await enclave.execute(env + contractCode);
 * console.log('Result:', execution.result);
 * ```
 */
