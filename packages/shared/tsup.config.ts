import { defineConfig } from 'tsup'
// @ts-ignore
import pkg from './package.json'

const globalName = 'SoftEnclaveShared'

export default defineConfig([
  // 1) CommonJS (CJS) build (unbundled)
  {
    entry: ['src/**/*.ts'],
    outDir: 'dist/cjs',
    format: ['cjs'],
    bundle: false,
    splitting: false,
    clean: true,
    keepNames: true,
    dts: {
      resolve: true,
      entry: 'src/index.ts',
    },
    sourcemap: true,
    minify: false,
    banner: {
      js: `/* Soft Enclave Shared - CJS (${pkg.name} v${pkg.version}) */`,
    },
  },

  // 2) ESM build (unbundled)
  {
    entry: ['src/**/*.ts'],
    outDir: 'dist/esm',
    format: ['esm'],
    shims: true,
    bundle: false,
    splitting: false,
    clean: true,
    keepNames: true,
    dts: {
      resolve: true,
      entry: 'src/index.ts',
    },
    sourcemap: true,
    minify: false,
    banner: {
      js: `/* Soft Enclave Shared - ESM (${pkg.name} v${pkg.version}) */`,
    },
  },

  // 3) IIFE/UMD build for browser
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
      js: `/* Soft Enclave Shared - IIFE (${pkg.name} v${pkg.version}) */`,
    },
  },
])
