/**
 * Message types for host-enclave communication
 */

/**
 * Protocol version
 */
export const PROTOCOL_VERSION = 'v1';

/**
 * Versioned AAD (Additional Authenticated Data) strings
 *
 * Version 1.1 improvement: All AAD strings include protocol version
 * for future extensibility and migration.
 *
 * Format: soft-enclave/op={operation}/{version}
 */
export const AAD = {
  EXECUTE: `soft-enclave/op=execute/${PROTOCOL_VERSION}`,
  EXECUTE_RESULT: `soft-enclave/op=execute-result/${PROTOCOL_VERSION}`,
  SIGN_TRANSACTION_KEY: `soft-enclave/op=sign-tx-key/${PROTOCOL_VERSION}`,
  SIGN_TRANSACTION_TX: `soft-enclave/op=sign-tx-data/${PROTOCOL_VERSION}`,
  SIGN_RESULT: `soft-enclave/op=sign-result/${PROTOCOL_VERSION}`
};

export const MessageType = {
  // Initialization
  INIT: 'INIT',
  INIT_SUCCESS: 'INIT_SUCCESS',
  INIT_ERROR: 'INIT_ERROR',

  // Key exchange
  KEY_EXCHANGE: 'KEY_EXCHANGE',
  KEY_EXCHANGE_RESPONSE: 'KEY_EXCHANGE_RESPONSE',

  // Execution
  EXECUTE: 'EXECUTE',
  EXECUTE_RESULT: 'EXECUTE_RESULT',
  EXECUTE_ERROR: 'EXECUTE_ERROR',

  // Signing operations
  SIGN_TRANSACTION: 'SIGN_TRANSACTION',
  SIGN_RESULT: 'SIGN_RESULT',

  // Status
  PING: 'PING',
  PONG: 'PONG',

  // Metrics
  GET_METRICS: 'GET_METRICS',
  METRICS: 'METRICS'
};

/**
 * @typedef {Object} Message
 * @property {string} type - Message type from MessageType
 * @property {string} id - Unique message ID for request/response matching
 * @property {any} payload - Message payload (encrypted for sensitive data)
 * @property {number} timestamp - Message timestamp
 */

/**
 * Create a new message
 */
export function createMessage(type, payload = null) {
  return {
    type,
    id: generateMessageId(),
    payload,
    timestamp: Date.now()
  };
}

/**
 * Generate a unique message ID
 */
export function generateMessageId() {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * @typedef {Object} ExecutionRequest
 * @property {string} code - JavaScript code to execute in QuickJS
 * @property {any} context - Context data (encrypted)
 * @property {number} timeout - Execution timeout in ms
 */

/**
 * @typedef {Object} ExecutionResult
 * @property {any} result - Execution result (encrypted)
 * @property {number} duration - Execution duration in ms
 * @property {ExecutionMetrics} metrics - Execution metrics
 */

/**
 * @typedef {Object} ExecutionMetrics
 * @property {number} keyExposureMs - Time key was exposed in plaintext
 * @property {number} totalDurationMs - Total operation duration
 * @property {boolean} memoryZeroed - Whether memory was explicitly zeroed
 */

/**
 * @typedef {Object} SignTransactionRequest
 * @property {Uint8Array} encryptedKey - Encrypted private key
 * @property {any} transaction - Transaction to sign
 */

/**
 * @typedef {Object} SignResult
 * @property {Uint8Array} signature - Transaction signature
 * @property {ExecutionMetrics} metrics - Execution metrics
 */
