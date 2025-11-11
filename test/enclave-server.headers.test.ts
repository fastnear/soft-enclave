// @vitest-environment node
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('Enclave Server - Security Headers', () => {
  it('MUST define strict COOP/COEP/CSP and frame-ancestors', () => {
    const file = path.resolve(__dirname, '..', 'enclave-server.js');
    const src = fs.readFileSync(file, 'utf-8');

    // Extract the function with proper brace matching
    const fnStart = src.indexOf('function getSecurityHeaders()');
    expect(fnStart, 'getSecurityHeaders() must exist').toBeGreaterThan(-1);

    let braceCount = 0;
    let inFunction = false;
    let fnEnd = fnStart;

    for (let i = fnStart; i < src.length; i++) {
      if (src[i] === '{') {
        braceCount++;
        inFunction = true;
      } else if (src[i] === '}') {
        braceCount--;
        if (inFunction && braceCount === 0) {
          fnEnd = i + 1;
          break;
        }
      }
    }

    const fnBody = src.slice(fnStart, fnEnd);

    // Evaluate function with HOST_ORIGIN parameter
    const getHeaders = new Function(
      'HOST_ORIGIN',
      fnBody + '; return getSecurityHeaders();'
    ) as (host: string) => Record<string, string | string[]>;
    const headers = getHeaders('http://localhost:5173');

    expect(headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
    expect(headers['Cross-Origin-Embedder-Policy']).toBe('require-corp');

    const csp = Array.isArray(headers['Content-Security-Policy'])
      ? headers['Content-Security-Policy'].join('; ')
      : String(headers['Content-Security-Policy']);

    expect(csp).toMatch(/default-src\s+'none'/);
    expect(csp).toMatch(/connect-src\s+'self'/);
    // Allow either exact host embedding or hard block via 'none'
    expect(csp).toMatch(/frame-ancestors\s+(http:\/\/localhost:5173|'none')/);
  });
});
