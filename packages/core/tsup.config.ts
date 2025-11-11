import { defineConfig } from 'tsup'
// @ts-ignore
import pkg from './package.json'

export default defineConfig([
  // 1) CommonJS (CJS) build (unbundled, no DTS)
  {
    entry: ['src/**/*.ts'],
    outDir: 'dist/cjs',
    format: ['cjs'],
    bundle: false,
    splitting: false,
    clean: true,
    keepNames: true,
    dts: false,  // Only ESM build generates DTS
    sourcemap: true,
    minify: false,
    external: ['@near/soft-enclave-worker', '@near/soft-enclave-iframe'],
    banner: {
      js: `/* Soft Enclave Core - CJS (${pkg.name} v${pkg.version}) */`,
    },
  },

  // 2) ESM build (unbundled, with DTS)
  {
    entry: ['src/**/*.ts'],
    outDir: 'dist/esm',
    format: ['esm'],
    shims: true,
    bundle: false,
    splitting: false,
    clean: true,
    keepNames: true,
    dts: true,  // Generate DTS for all entry files
    sourcemap: true,
    minify: false,
    external: ['@near/soft-enclave-worker', '@near/soft-enclave-iframe'],
    banner: {
      js: `/* Soft Enclave Core - ESM (${pkg.name} v${pkg.version}) */`,
    },
  },

  // Note: No IIFE build for core package - it only contains dynamic imports
  // that resolve to worker/iframe packages at runtime
])
