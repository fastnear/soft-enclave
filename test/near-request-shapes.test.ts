// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { makeAccessKeyRequest, makeSendTransactionRequest } from '../packages/near/src/enclave/near-enclave';

describe('NEAR RPC Request Shape', () => {
  it('MUST build view_access_key with finality: final', () => {
    const { req } = makeAccessKeyRequest({
      rpcUrl: 'https://rpc.testnet.near.org',
      accountId: 'you.testnet',
      publicKey: 'ed25519:abc'
    });
    expect(req.method).toBe('query');
    expect(req.params.request_type).toBe('view_access_key');
    expect(req.params.finality).toBe('final');
  });

  it('MUST build send_tx with signed_tx_base64', () => {
    const { req } = makeSendTransactionRequest({
      rpcUrl: 'https://rpc.testnet.near.org',
      signedTransaction: 'AAAA',
    });
    expect(req.method).toBe('send_tx');
    expect(req.params.signed_tx_base64).toBe('AAAA');
  });
});
