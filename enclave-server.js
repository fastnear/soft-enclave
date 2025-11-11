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

const PORT = 8081;
const HOST_ORIGIN = 'http://localhost:3000'; // Expected parent origin

// MIME types for proper content-type headers
const MIME_TYPES = {
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
  '.json': 'application/json; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
};

/**
 * Generate strict security headers for enclave origin
 */
function getSecurityHeaders() {
  return {
    // Cross-Origin Isolation
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',

    // Content Security Policy - MAXIMUM RESTRICTION
    'Content-Security-Policy': [
      "default-src 'none'",           // Block everything by default
      "script-src 'self'",            // Only allow scripts from our origin
      "connect-src 'self'",           // Only allow connections to our origin
      "worker-src 'self'",            // Only allow workers from our origin
      `frame-ancestors ${HOST_ORIGIN}`, // Only allow embedding from expected parent
      "base-uri 'none'",              // Prevent base tag injection
      "form-action 'none'",           // No form submissions
      "object-src 'none'",            // No plugins
      "font-src 'none'",              // No fonts
      "img-src 'none'",               // No images
      "media-src 'none'",             // No media
      "style-src 'none'",             // No stylesheets
      "upgrade-insecure-requests"     // Force HTTPS in production
    ].join('; '),

    // Additional Security Headers
    'X-Content-Type-Options': 'nosniff',        // Prevent MIME sniffing
    'X-Frame-Options': 'DENY',                  // Prevent framing (defense-in-depth)
    'Referrer-Policy': 'no-referrer',           // Don't leak referrer
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()', // Disable unnecessary APIs

    // CORS - Allow requests from expected parent origin
    'Access-Control-Allow-Origin': HOST_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
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

  // Only allow GET requests
  if (req.method !== 'GET') {
    res.writeHead(405, {
      ...getSecurityHeaders(),
      'Allow': 'GET, OPTIONS',
    });
    res.end('Method Not Allowed');
    return;
  }

  // Map URL to file path
  let filePath;

  if (req.url === '/' || req.url === '/enclave-worker.js') {
    // Main worker entry point
    filePath = join(__dirname, 'src/enclave/enclave-worker.js');
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
  console.log('  /enclave-worker.js → src/enclave/enclave-worker.js');
  console.log('  /src/shared/*      → Shared utilities');
  console.log('  /node_modules/*    → Dependencies');
  console.log('━'.repeat(60));
  console.log('\nPress Ctrl+C to stop\n');
});

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
