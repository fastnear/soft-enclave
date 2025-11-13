import { defineConfig } from 'vite';
import { resolve } from 'path';

// Bundle the enclave app into a single file that includes all dependencies (tweetnacl, borsh, etc.)
// This ensures the cross-origin iframe can load everything without bare import specifiers

export default defineConfig({
  build: {
    target: 'es2020',
    sourcemap: true,
    emptyOutDir: false, // Don't delete other files in output dir
    outDir: resolve(__dirname, 'packages/iframe/dist/enclave-bundle'),
    lib: {
      entry: resolve(__dirname, 'packages/iframe/src/enclave/enclave-main.ts'),
      formats: ['es'],
      fileName: () => 'enclave-main.bundle.js'
    },
    rollupOptions: {
      output: {
        inlineDynamicImports: true, // Bundle all dynamic imports
      }
    }
  },
  // Pre-bundle these deps so they're included
  optimizeDeps: {
    include: ['tweetnacl', 'borsh']
  },
  resolve: {
    alias: {
      // Ensure paths resolve correctly during build
      '@': resolve(__dirname, 'packages')
    }
  }
});
