/**
 * NEAR Storage Shim
 *
 * Provides a minimal NEAR storage API for contracts running in the enclave.
 * Ported from near-outlayer's quickjs-enclave.ts implementation.
 *
 * This shim allows contracts to use:
 * - near.storageRead(key) - Read from contract state
 * - near.storageWrite(key, value) - Write to contract state
 * - near.log(...args) - Log messages (collected for debugging)
 *
 * Usage:
 * ```javascript
 * import { createNEARShim } from './near/storage-shim.js';
 *
 * const shim = createNEARShim(contractState);
 * const shimCode = shim.getShimCode();
 *
 * // Inject before contract code
 * await enclave.execute(shimCode + contractCode, { state: contractState });
 * ```
 */

/**
 * Create NEAR storage shim
 *
 * @param {object} initialState - Initial contract state (key-value pairs)
 * @returns {object} Shim object with getShimCode() and extractState() methods
 */
export function createNEARShim(initialState = {}) {
  return {
    /**
     * Get the shim code to inject into enclave
     *
     * This creates a `near` global object with storage and logging methods.
     * The state is passed via context and mutations are tracked.
     *
     * @returns {string} JavaScript code to inject
     */
    getShimCode() {
      const stateJson = JSON.stringify(initialState);

      return `
// NEAR Storage Shim
// =================
// Provides minimal NEAR storage API for contract execution

// Initialize state from context
const __STATE__ = ${stateJson};
const __LOGS__ = [];

// NEAR API object
const near = Object.freeze({
  /**
   * Read value from storage
   * @param {string} key - Storage key
   * @returns {any} Value or undefined
   */
  storageRead: (key) => {
    const value = __STATE__[key];
    __LOGS__.push(\`[storage] Read "\${key}": \${JSON.stringify(value)}\`);
    return value;
  },

  /**
   * Write value to storage
   * @param {string} key - Storage key
   * @param {any} value - Value to store
   */
  storageWrite: (key, value) => {
    __STATE__[key] = value;
    __LOGS__.push(\`[storage] Write "\${key}": \${JSON.stringify(value)}\`);
  },

  /**
   * Log messages (for debugging)
   * @param {...any} args - Values to log
   */
  log: (...args) => {
    const message = args.map(a =>
      typeof a === 'string' ? a : JSON.stringify(a)
    ).join(' ');
    __LOGS__.push(\`[contract] \${message}\`);
  }
});

// Make near globally available and harden it
globalThis.near = near;

// Lock the 'near' global to prevent reassignment
try {
  Object.defineProperty(globalThis, 'near', {
    value: near,
    enumerable: true,
    configurable: false,
    writable: false
  });
} catch (e) {
  // Already defined or locked - acceptable
}
`;
    },

    /**
     * Extract state and logs from execution result
     *
     * After execution, contracts should return their state and logs.
     * This helper extracts them from the result.
     *
     * @param {any} result - Execution result
     * @returns {object} { state, logs, contractResult }
     */
    extractState(result) {
      // If result has __STATE__ and __LOGS__, extract them
      if (result && typeof result === 'object') {
        return {
          state: result.__STATE__ || initialState,
          logs: result.__LOGS__ || [],
          contractResult: result.result
        };
      }

      // Otherwise, return as-is
      return {
        state: initialState,
        logs: [],
        contractResult: result
      };
    }
  };
}

/**
 * Wrap contract code with NEAR shim and state management
 *
 * This is a convenience function that:
 * 1. Injects the NEAR shim
 * 2. Wraps the contract code
 * 3. Returns state and logs along with result
 *
 * @param {string} contractCode - Contract JavaScript code
 * @param {object} initialState - Initial state
 * @returns {string} Wrapped code ready for execution
 */
export function wrapWithNEARShim(contractCode, initialState = {}) {
  const shim = createNEARShim(initialState);
  const shimCode = shim.getShimCode();

  return `
${shimCode}

// Execute contract code
(function() {
  ${contractCode}

  // Return result with state and logs
  return {
    result: typeof result !== 'undefined' ? result : null,
    __STATE__,
    __LOGS__
  };
})();
`;
}

/**
 * Execute contract with NEAR shim
 *
 * High-level helper that wraps a contract and executes it in an enclave.
 *
 * @param {object} enclave - Enclave instance
 * @param {string} contractCode - Contract code
 * @param {object} state - Current state
 * @param {object} context - Additional context
 * @returns {Promise<object>} { result, state, logs, metrics }
 */
export async function executeWithNEAR(enclave, contractCode, state = {}, context = {}) {
  const wrappedCode = wrapWithNEARShim(contractCode, state);

  const execution = await enclave.execute(wrappedCode, context);

  // Extract state and logs from result
  const shim = createNEARShim(state);
  const extracted = shim.extractState(execution.result);

  return {
    result: extracted.contractResult,
    state: extracted.state,
    logs: extracted.logs,
    metrics: execution.metrics,
    totalDurationMs: execution.totalDurationMs
  };
}

/**
 * Example usage:
 *
 * ```javascript
 * import { executeWithNEAR } from './near/storage-shim.js';
 *
 * const contractCode = `
 *   function increment() {
 *     const count = near.storageRead('count') || 0;
 *     const newCount = count + 1;
 *     near.storageWrite('count', newCount);
 *     near.log('Incremented to', newCount);
 *     return newCount;
 *   }
 *
 *   const result = increment();
 * `;
 *
 * const { result, state, logs } = await executeWithNEAR(
 *   enclave,
 *   contractCode,
 *   { count: 5 }
 * );
 *
 * console.log('Result:', result);     // 6
 * console.log('New state:', state);   // { count: 6 }
 * console.log('Logs:', logs);         // ['[storage] Read "count": 5', ...]
 * ```
 */
