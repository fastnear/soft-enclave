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
    external: ['@fastnear/soft-enclave-core'],
    banner: {
      js: `/* Soft Enclave Worker - CJS (${pkg.name} v${pkg.version}) */`,
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
    external: ['@fastnear/soft-enclave-core'],
    banner: {
      js: `/* Soft Enclave Worker - ESM (${pkg.name} v${pkg.version}) */`,
    },
  },

  // Note: No IIFE build for worker package - it depends on core which has dynamic imports
])
