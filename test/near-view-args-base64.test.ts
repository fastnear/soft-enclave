// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { makeViewFunctionRequest } from '../packages/near/src/enclave/near-enclave';

describe('NEAR View Args Encoding', () => {
  it('MUST base64-encode UTF-8 args correctly', () => {
    const args = { message: 'Привет 👋' };
    const { req } = makeViewFunctionRequest({
      rpcUrl: 'https://rpc.testnet.near.org',
      contractId: 'example.testnet',
      methodName: 'get_greeting',
      args,
      finality: 'optimistic'
    });
    const b64 = (req as any).params.args_base64;
    const buf = Buffer.from(b64, 'base64');
    const decoded = JSON.parse(new TextDecoder().decode(buf));
    expect(decoded).toEqual(args);
  });
});
