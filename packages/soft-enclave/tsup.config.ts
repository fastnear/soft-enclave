import { defineConfig } from 'tsup'
// @ts-ignore
import pkg from './package.json'

const globalName = 'SoftEnclave'

const footerRedefiningGlobal = `
try {
  Object.defineProperty(globalThis, '${globalName}', {
    value: ${globalName},
    enumerable: true,
    configurable: false,
  });
} catch (error) {
  console.error('Could not define global "SoftEnclave" object', error);
}
`

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
      js: `/* NEAR Soft Enclave - CJS (${pkg.name} v${pkg.version}) */\n` +
        `/* https://www.npmjs.com/package/${pkg.name}/v/${pkg.version} */`,
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
      js: `/* NEAR Soft Enclave - ESM (${pkg.name} v${pkg.version}) */\n` +
        `/* https://www.npmjs.com/package/${pkg.name}/v/${pkg.version} */`,
    },
  },

  // 3) IIFE/UMD build for browser with hardened global
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
      js: `/* NEAR Soft Enclave - IIFE (${pkg.name} v${pkg.version}) */\n` +
        `/* https://www.npmjs.com/package/${pkg.name}/v/${pkg.version} */`,
    },
    footer: {
      js: footerRedefiningGlobal,
    },
  },
])
