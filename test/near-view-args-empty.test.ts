// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { makeViewFunctionRequest } from '../packages/near/src/enclave/near-enclave';

describe('NEAR View Args – empty', () => {
  it('encodes empty args as empty base64 string', () => {
    const { req } = makeViewFunctionRequest({
      rpcUrl: 'https://rpc.testnet.near.org',
      contractId: 'example.testnet',
      methodName: 'get_greeting',
      args: {},                // deliberate: empty
      finality: 'optimistic'
    });
    expect((req as any).params.args_base64).toBe('');
  });
});
