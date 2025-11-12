import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    // Use node environment with browser polyfills
    environment: 'node',

    // Setup files to run before tests
    setupFiles: ['./test/setup.js'],

    // Global test timeout
    testTimeout: 30000,

    // Enable globals like describe, it, expect
    globals: true,

    // Suppress expected uncaught errors from primordial freezing
    onUncaughtException(error) {
      if (error && error.message && error.message.includes("Cannot assign to read only property 'constructor'")) {
        // Expected error during Object.freeze() - safe to ignore
        return;
      }
      // Log unexpected errors
      console.error('Uncaught exception:', error);
    },

    // Coverage configuration
    coverage: {
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'test/',
        'demo/',
        'dist/',
        '**/*.d.ts',
        '**/*.config.js',
        '**/mockData.js'
      ]
    }
  },

  resolve: {
    alias: {
      '@fastnear/soft-enclave': path.resolve(__dirname, './packages/soft-enclave/src/index.ts'),
      '@fastnear/soft-enclave-core': path.resolve(__dirname, './packages/core/src/index.ts'),
      '@fastnear/soft-enclave-shared': path.resolve(__dirname, './packages/shared/src/index.ts'),
      '@fastnear/soft-enclave-worker': path.resolve(__dirname, './packages/worker/src/index.ts'),
      '@fastnear/soft-enclave-iframe': path.resolve(__dirname, './packages/iframe/src/index.ts'),
      '@fastnear/soft-enclave-near': path.resolve(__dirname, './packages/near/src/index.ts'),
    }
  }
});