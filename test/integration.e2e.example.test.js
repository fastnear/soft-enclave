// @vitest-environment node
import { describe as _describe, it, expect, beforeAll, afterAll } from 'vitest';
const describe = (process.env.RUN_E2E === '1' ? _describe : _describe.skip);

import { HybridSecureEnclave } from '../src/host/hybrid-enclave.js';

describe('End-to-End Integration: Context-Bound Sessions + AAD', () => {
  let enclave;
  afterAll(async () => { try { await enclave?.shutdown?.(); } catch {} });

  it('initializes and evaluates code with AAD-bound ciphertexts', async () => {
    // This block will execute only when RUN_E2E=1
    enclave = new HybridSecureEnclave({
      workerUrl: 'http://localhost:8081/enclave-worker.js',
      wasmModule: null // Will be loaded by worker
    });

    await enclave.initialize();

    const result = await enclave.execute('40 + 2');
    expect(result.result).toBe(42);

    // Verify session key was established
    expect(enclave.sessionKey).toBeDefined();
    expect(enclave.sessionKey).not.toBeNull();
  });
});
