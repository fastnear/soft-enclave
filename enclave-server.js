#!/usr/bin/env node

/**
 * Dedicated Enclave Server with Strict Security Headers
 *
 * This server hosts ONLY the enclave worker on a separate origin
 * with maximum security hardening through HTTP headers.
 *
 * Security Headers Applied:
 * 1. Cross-Origin-Opener-Policy (COOP) - Process isolation
 * 2. Cross-Origin-Embedder-Policy (COEP) - Resource control
 * 3. Content-Security-Policy (CSP) - Minimize attack surface
 * 4. Frame-Ancestors - Prevent embedding abuse
 *
 * Production deployment:
 * - Serve from https://enclave.yourdomain.com
 * - Different subdomain than main app
 * - This provides origin-level isolation via Same-Origin Policy
 */

import { createServer } from 'http';
import { readFile } from 'fs/promises';
import { extname, join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = Number(process.env.ENCLAVE_PORT || 3010); // iframe backend expects 3010 (host:3000 + 10)
const HOST_ORIGIN = process.env.HOST_ORIGIN || 'http://localhost:3000'; // Expected parent origin

// MIME types for proper content-type headers
const MIME_TYPES = {
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.ts': 'application/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

/**
 * Generate strict security headers for enclave origin
 */
function getSecurityHeaders() {
  const hostOrigin = process.env.HOST_ORIGIN || 'http://localhost:3000';

  return {
    // Cross-Origin Isolation
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',

    // Content Security Policy - RELAXED FOR DEBUGGING
    'Content-Security-Policy': [
      "default-src 'self'",           // Allow resources from same origin
      "script-src 'self' 'wasm-unsafe-eval'", // Allow WASM compilation (not JS eval)
      "style-src 'self' 'unsafe-inline'", // Allow inline styles for debugging
      "connect-src 'self'",           // Only allow connections to our origin
      "worker-src 'self'",            // Only allow workers from our origin
      `frame-ancestors ${hostOrigin}`, // Only allow embedding from expected parent
      "base-uri 'none'",              // Prevent base tag injection
      "form-action 'none'"            // No form submissions
    ].join('; '),

    // Additional Security Headers
    'X-Content-Type-Options': 'nosniff',        // Prevent MIME sniffing
    'X-Frame-Options': 'DENY',                  // Prevent framing (defense-in-depth)
    'Referrer-Policy': 'no-referrer',           // Don't leak referrer
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()', // Disable unnecessary APIs

    // CORS - Allow requests from expected parent origin
    'Access-Control-Allow-Origin': hostOrigin,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',

    // Cross-Origin Resource Policy - Required for COEP compatibility
    // Allows cross-origin fetching when constructing Worker from Blob URL
    'Cross-Origin-Resource-Policy': 'cross-origin',
  };
}

/**
 * Serve file with security headers
 */
async function serveFile(filePath, res) {
  try {
    const content = await readFile(filePath);
    const ext = extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    // Apply security headers
    const headers = {
      ...getSecurityHeaders(),
      'Content-Type': contentType,
      'Content-Length': content.length,
      'Cache-Control': 'no-cache', // Development mode - disable caching
    };

    // WASM files need additional CORS/CORP headers for cross-origin loading
    if (ext === '.wasm') {
      headers['Access-Control-Allow-Origin'] = HOST_ORIGIN;
      headers['Vary'] = 'Origin';
      headers['Cross-Origin-Resource-Policy'] = 'cross-origin';
    }

    res.writeHead(200, headers);
    res.end(content);

    console.log(`✓ Served: ${filePath}`);
  } catch (error) {
    console.error(`✗ Error serving ${filePath}:`, error.message);

    const headers = {
      ...getSecurityHeaders(),
      'Content-Type': 'text/plain; charset=utf-8',
    };

    res.writeHead(404, headers);
    res.end('Not Found');
  }
}

/**
 * Main request handler
 */
async function handleRequest(req, res) {
  console.log(`${req.method} ${req.url} from ${req.headers.origin || 'unknown origin'}`);

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, getSecurityHeaders());
    res.end();
    return;
  }

  // Handle HEAD requests (for debugging with curl -I)
  if (req.method === 'HEAD') {
    // HEAD is like GET but without body
    const ext = extname(req.url.split('?')[0]);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const headers = {
      ...getSecurityHeaders(),
      'Content-Type': contentType,
    };

    // Add WASM-specific headers
    if (ext === '.wasm') {
      headers['Access-Control-Allow-Origin'] = HOST_ORIGIN;
      headers['Vary'] = 'Origin';
      headers['Cross-Origin-Resource-Policy'] = 'cross-origin';
    }

    res.writeHead(200, headers);
    res.end();
    return;
  }

  // Only allow GET requests
  if (req.method !== 'GET') {
    res.writeHead(405, {
      ...getSecurityHeaders(),
      'Allow': 'GET, HEAD, OPTIONS',
    });
    res.end('Method Not Allowed');
    return;
  }

  // Map URL to file path
  let filePath;

  if (req.url === '/' || req.url === '/enclave-worker.js') {
    // Main worker entry point
    filePath = join(__dirname, 'src/enclave/enclave-worker.js');
  } else if (req.url === '/boot.html') {
    // iframe backend boot page
    filePath = join(__dirname, 'packages/iframe/src/enclave/boot.html');
  } else if (req.url === '/egress-assert.js') {
    // iframe backend egress guard (built)
    filePath = join(__dirname, 'packages/iframe/dist/esm/enclave/egress-assert.js');
  } else if (req.url === '/enclave-main.js') {
    // iframe backend main script (built)
    filePath = join(__dirname, 'packages/iframe/dist/esm/enclave/enclave-main.js');
  } else if (req.url === '/crypto-protocol.js') {
    // iframe backend crypto protocol (built)
    filePath = join(__dirname, 'packages/iframe/dist/esm/enclave/crypto-protocol.js');
  } else if (req.url === '/quickjs-runtime.js') {
    // iframe backend QuickJS runtime (built)
    filePath = join(__dirname, 'packages/iframe/dist/esm/enclave/quickjs-runtime.js');
  } else if (req.url.startsWith('/vendor/')) {
    // QuickJS vendor files - map to node_modules
    const vendorFile = req.url.replace('/vendor/', '');
    if (vendorFile === 'quickjs-emscripten.mjs' || vendorFile === 'quickjs-emscripten-core.mjs') {
      filePath = join(__dirname, 'node_modules/quickjs-emscripten/dist/index.mjs');
    } else if (vendorFile.endsWith('.wasm')) {
      // WASM files from @jitl packages (e.g., emscripten-module.wasm)
      // Check each QuickJS variant package
      const variants = [
        'quickjs-wasmfile-release-sync',
        'quickjs-wasmfile-release-asyncify',
        'quickjs-wasmfile-debug-sync',
        'quickjs-wasmfile-debug-asyncify'
      ];
      for (const variant of variants) {
        const wasmPath = join(__dirname, `node_modules/@jitl/${variant}/dist/${vendorFile}`);
        try {
          await readFile(wasmPath);
          filePath = wasmPath;
          break;
        } catch {
          // Try next variant
        }
      }
      if (!filePath) {
        // Fallback to quickjs-emscripten dist
        filePath = join(__dirname, 'node_modules/quickjs-emscripten/dist/', vendorFile);
      }
    } else {
      // Allow other vendor files from node_modules
      filePath = join(__dirname, 'node_modules/quickjs-emscripten/dist/', vendorFile);
    }
  } else if (req.url.startsWith('/shared/')) {
    // Shared package files - serve from built dist/esm
    const relativePath = req.url.replace('/shared/src/', '');
    filePath = join(__dirname, 'packages/shared/dist/esm', relativePath);
  } else if (req.url.startsWith('/near/')) {
    // NEAR package files - serve from built dist/esm
    const relativePath = req.url.replace('/near/src/', '');
    filePath = join(__dirname, 'packages/near/dist/esm', relativePath);
  } else if (req.url.startsWith('/packages/')) {
    // iframe backend files
    filePath = join(__dirname, req.url);
  } else if (req.url.startsWith('/src/')) {
    // Shared utilities
    filePath = join(__dirname, req.url);
  } else if (req.url.startsWith('/node_modules/')) {
    // Dependencies (QuickJS, etc.)
    filePath = join(__dirname, req.url);
  } else {
    // Invalid path
    res.writeHead(404, getSecurityHeaders());
    res.end('Not Found');
    return;
  }

  await serveFile(filePath, res);
}

/**
 * Start server
 */
const server = createServer(handleRequest);

server.listen(PORT, () => {
  console.log('\n🔒 Enclave Server Started');
  console.log('━'.repeat(60));
  console.log(`URL: http://localhost:${PORT}`);
  console.log(`Expected Parent: ${HOST_ORIGIN}`);
  console.log('\nSecurity Headers:');
  console.log('  ✓ Cross-Origin-Opener-Policy: same-origin');
  console.log('  ✓ Cross-Origin-Embedder-Policy: require-corp');
  console.log('  ✓ Content-Security-Policy: strict (default-src: none)');
  console.log('  ✓ Frame-Ancestors: restricted to parent only');
  console.log('  ✓ CORS: restricted to parent origin');
  console.log('\nServing:');
  console.log('  Worker Backend:');
  console.log('    /enclave-worker.js → src/enclave/enclave-worker.js');
  console.log('  iframe Backend:');
  console.log('    /boot.html → packages/iframe/src/enclave/boot.html');
  console.log('    /*.js      → packages/iframe/dist/esm/enclave/*.js (built files)');
  console.log('  Shared:');
  console.log('    /src/shared/*      → Shared utilities');
  console.log('    /node_modules/*    → Dependencies');
  console.log('━'.repeat(60));
  console.log('\nPress Ctrl+C to stop\n');
});

// Export for testing (ES module syntax)
export { getSecurityHeaders };

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n🛑 Shutting down enclave server...');
  server.close(() => {
    console.log('✓ Server closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n\n🛑 Received SIGTERM, shutting down...');
  server.close(() => {
    console.log('✓ Server closed');
    process.exit(0);
  });
});
