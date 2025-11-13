import { defineConfig } from 'vitest/config';
import path from 'path';

// Gate experimental and environment-specific test suites
const runE2E = process.env.RUN_E2E === '1';
const runHPKE = process.env.RUN_HPKE === '1';

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

    // Deterministic threading for crypto/spies on CI
    threads: false,

    // Test file patterns
    include: ['test/**/*.test.{ts,js}'],
    exclude: [
      ...(runE2E ? [] : ['test/integration*.test.*', 'test/**/integration/**']),
      ...(runHPKE ? [] : ['test/hpke-protocol.test.js'])
    ],

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