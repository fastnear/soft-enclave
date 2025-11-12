// @vitest-environment node
import { describe, it, expect, vi } from 'vitest';
import { makeEgressGuard, type JsonRpcRequest } from '../packages/near/src/host/rpc';

describe('Egress Guard - HTTPS & Fallback', () => {
  it('MUST block non-HTTPS for non-localhost', async () => {
    const guard = makeEgressGuard({
      allowHosts: ['rpc.testnet.near.org'],
      allowMethods: ['query'],
      requireHttps: true
    });
    const req: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'query', params: {} };
    await expect(guard.post('http://rpc.testnet.near.org', req)).rejects.toThrow(/Non-HTTPS/);
  });

  it('MUST allow HTTP only for localhost', async () => {
    const guard = makeEgressGuard({
      allowHosts: ['localhost:1234'],
      allowMethods: ['query'],
      requireHttps: true
    });
    const req: JsonRpcRequest = { jsonrpc: '2.0', id: 1, method: 'query', params: {} };
    const resp = { ok: true, body: null, text: async () => JSON.stringify({ jsonrpc:'2.0', id:1, result:{ ok:true } }) } as any;
    const spy = vi.spyOn(globalThis, 'fetch' as any).mockResolvedValue(resp);
    const out = await guard.post('http://localhost:1234', req);
    expect(out.result.ok).toBe(true);
    spy.mockRestore();
  });

  it('MUST fall back to broadcast_tx_commit when send_tx fails and fallback allowed', async () => {
    const guard = makeEgressGuard({
      allowHosts: ['rpc.testnet.near.org'],
      allowMethods: ['send_tx', 'broadcast_tx_commit'],
      requireHttps: false
    });
    const reqSendTx: JsonRpcRequest = {
      jsonrpc: '2.0', id: 42, method: 'send_tx', params: { signed_tx_base64: 'AAAA' }
    };
    const errResp = { ok: false, body: null, text: async () => JSON.stringify({ error: { code: -32601, message: 'Method not found' } }) } as any;
    const okResp  = { ok: true,  body: null, text: async () => JSON.stringify({ jsonrpc:'2.0', id:42, result:{ status: 'Completed' } }) } as any;

    const spy = vi.spyOn(globalThis, 'fetch' as any)
      .mockResolvedValueOnce(errResp as any)
      .mockResolvedValueOnce(okResp as any);

    const out = await guard.post('http://rpc.testnet.near.org', reqSendTx);
    expect(out.result.status).toBe('Completed');
    spy.mockRestore();
  });
});
