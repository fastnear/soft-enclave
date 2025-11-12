import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    threads: false, // Serialize tests to avoid race conditions in crypto-heavy suites
    testTimeout: 30000,
    include: ['test/**/*.test.ts', 'test/**/*.test.js'],
    exclude: ['**/node_modules/**', '**/dist/**']
  }
});
