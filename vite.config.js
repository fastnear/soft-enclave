import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: 'demo',
  resolve: {
    alias: {
      '@fastnear/soft-enclave': path.resolve(__dirname, './packages/soft-enclave/src/index.ts'),
      '@fastnear/soft-enclave-core': path.resolve(__dirname, './packages/core/src/index.ts'),
      '@fastnear/soft-enclave-shared': path.resolve(__dirname, './packages/shared/src/index.ts'),
      '@fastnear/soft-enclave-worker': path.resolve(__dirname, './packages/worker/src/index.ts'),
      '@fastnear/soft-enclave-iframe': path.resolve(__dirname, './packages/iframe/src/index.ts'),
      '@fastnear/soft-enclave-near': path.resolve(__dirname, './packages/near/src/index.ts'),
    }
  },
  server: {
    port: 3000,
    strictPort: true, // Fail if port is already in use instead of trying another port
    cors: true,
    headers: {
      // Cross-Origin Isolation for process isolation
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',

      // Content Security Policy for host origin
      // Less strict than enclave, but still defensive
      'Content-Security-Policy': [
        "default-src 'self'",                    // Only load resources from our origin
        "script-src 'self' 'unsafe-inline'",     // Allow inline scripts for Vite HMR
        "connect-src 'self' http://localhost:3010 ws://localhost:* https://rpc.testnet.near.org https://rpc.mainnet.near.org", // Allow enclave, HMR, and NEAR RPC
        "worker-src http://localhost:8081",      // Allow cross-origin worker (different port from iframe)
        "frame-src 'self' http://localhost:3010", // Allow cross-origin iframe (iframe backend uses port 3010)
        "child-src 'self' http://localhost:3010", // Legacy fallback for frame-src
        "style-src 'self' 'unsafe-inline'",      // Allow inline styles for demo
        "img-src 'self' data:",                  // Allow images
        "font-src 'self'",                       // Allow fonts
        "base-uri 'self'",                       // Restrict base tag
        "form-action 'self'",                    // Restrict form submissions
        "frame-ancestors 'none'",                // Prevent being framed
        "upgrade-insecure-requests"              // Force HTTPS in production
      ].join('; '),

      // Additional security headers
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
  },
  build: {
    outDir: '../dist',
    rollupOptions: {
      input: {
        main: 'demo/index.html',
        worker: 'src/enclave/enclave-worker.js'
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'worker') {
            return 'enclave/enclave-worker.js';
          }
          return '[name]-[hash].js';
        }
      }
    }
  },
  optimizeDeps: {
    include: ['quickjs-emscripten']
  }
});
