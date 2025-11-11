import { defineConfig } from 'tsup'
// @ts-ignore
import pkg from './package.json'

const globalName = 'SoftEnclaveNEAR'

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
    banner: {
      js: `/* Soft Enclave NEAR - CJS (${pkg.name} v${pkg.version}) */`,
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
    banner: {
      js: `/* Soft Enclave NEAR - ESM (${pkg.name} v${pkg.version}) */`,
    },
  },

  // 3) IIFE/UMD build for browser (bundled)
  {
    entry: {
      browser: 'src/index.ts',
    },
    outDir: 'dist/umd',
    format: ['iife'],
    globalName,
    bundle: true,
    splitting: false,
    clean: true,
    keepNames: true,
    dts: false,
    sourcemap: true,
    minify: false,
    platform: 'browser',
    banner: {
      js: `/* Soft Enclave NEAR - IIFE (${pkg.name} v${pkg.version}) */`,
    },
  },
])
