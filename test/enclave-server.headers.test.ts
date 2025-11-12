// @vitest-environment node
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { getSecurityHeaders } from '../enclave-server.js';

describe('Enclave Server - Security Headers', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    // Set HOST_ORIGIN for the test
    process.env.HOST_ORIGIN = 'http://localhost:5173';
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  it('MUST define strict COOP/COEP/CSP and frame-ancestors', () => {
    const headers = getSecurityHeaders();

    expect(headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
    expect(headers['Cross-Origin-Embedder-Policy']).toBe('require-corp');

    const csp = Array.isArray(headers['Content-Security-Policy'])
      ? headers['Content-Security-Policy'].join('; ')
      : String(headers['Content-Security-Policy']);

    expect(csp).toMatch(/default-src\s+'none'/);
    expect(csp).toMatch(/connect-src\s+'self'/);
    expect(csp).toMatch(/frame-ancestors\s+(http:\/\/localhost:5173|'none')/);
  });
});
