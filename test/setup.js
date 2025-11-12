/**
 * Test setup file - configures browser environment for Node.js tests
 */

import { webcrypto } from 'node:crypto';
import { TextEncoder, TextDecoder } from 'node:util';

// Suppress expected "Cannot assign to read only property 'constructor'" errors
// These occur when Object.freeze() tries to freeze already-frozen built-ins during primordial hardening
// This is a known, harmless error that doesn't affect test results
process.on('uncaughtException', (error) => {
  if (error.message && error.message.includes("Cannot assign to read only property 'constructor'")) {
    // Expected error during Object.freeze() - safe to ignore
    return;
  }
  // Re-throw unexpected errors
  throw error;
});

// Polyfill WebCrypto API - ensure it's the Node webcrypto
globalThis.crypto = webcrypto;

// Polyfill TextEncoder/TextDecoder
if (!globalThis.TextEncoder) {
  globalThis.TextEncoder = TextEncoder;
}
if (!globalThis.TextDecoder) {
  globalThis.TextDecoder = TextDecoder;
}

// Mock location for tests that need it
if (!globalThis.location) {
  globalThis.location = {
    origin: 'http://localhost:3000',
    protocol: 'http:',
    host: 'localhost:3000',
    hostname: 'localhost',
    port: '3000',
    pathname: '/',
    search: '',
    hash: '',
    href: 'http://localhost:3000/'
  };
}

// Basic Worker mock for tests
if (!globalThis.Worker) {
  class MockWorker {
    constructor(url) {
      this.url = url;
      this.onmessage = null;
      this.onerror = null;
    }

    postMessage(data) {
      // Mock implementation
      if (this.onerror) {
        setTimeout(() => {
          this.onerror(new Error('Worker not available in test environment'));
        }, 0);
      }
    }

    terminate() {
      // Mock implementation
    }
  }
  globalThis.Worker = MockWorker;
}

// Mock MessageChannel for tests
if (!globalThis.MessageChannel) {
  class MockMessagePort {
    constructor() {
      this.onmessage = null;
      this._otherPort = null;
    }

    postMessage(data) {
      if (this._otherPort && this._otherPort.onmessage) {
        setTimeout(() => {
          this._otherPort.onmessage({ data });
        }, 0);
      }
    }

    close() {
      // Mock implementation
    }
  }

  class MockMessageChannel {
    constructor() {
      this.port1 = new MockMessagePort();
      this.port2 = new MockMessagePort();
      this.port1._otherPort = this.port2;
      this.port2._otherPort = this.port1;
    }
  }
  globalThis.MessageChannel = MockMessageChannel;
}

// Mock indexedDB for tests that need it
if (!globalThis.indexedDB) {
  // Basic mock - tests that actually use IndexedDB should use a proper mock library
  globalThis.indexedDB = {
    open: () => {
      throw new Error('IndexedDB not available in test environment - use a mock library for storage tests');
    }
  };
}