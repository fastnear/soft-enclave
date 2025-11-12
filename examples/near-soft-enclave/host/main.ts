import { createHostChannel } from '../libs/secure-channel.js';
import { makeEgressGuard } from '@fastnear/soft-enclave-near';

const enclaveSrc = (window as any).ENCLAVE_ORIGIN ?? 'http://localhost:8081';
const targetOrigin = new URL(enclaveSrc).origin;

const iframe = document.getElementById('enclave') as HTMLIFrameElement;
iframe.src = `${enclaveSrc}/examples/near-soft-enclave/enclave/index.html`;

const policy = {
  allowHosts: ['rpc.testnet.near.org', 'rpc.mainnet.near.org'],
  allowMethods: ['query', 'block', 'send_tx', 'broadcast_tx_commit'],
  maxReqBytes: 64 * 1024,
  maxRespBytes: 1024 * 1024
};
const guard = makeEgressGuard(policy);

const status = document.getElementById('status')!;
const result = document.getElementById('result')!;

(async () => {
  const ch = await createHostChannel(iframe, targetOrigin);
  status.textContent = 'channel: ready';

  ch.onmessage(async (m: any) => {
    if (m?.t === 'egress-request') {
      try {
        const resp = await guard.post(m.url, m.req);
        await ch.send({ t: 'egress-response', ok: true, id: m.req.id, resp, originalType: m.originalType, opId: m.opId });
      } catch (e: any) {
        await ch.send({ t: 'egress-response', ok: false, id: m.req.id, error: String(e?.message || e), originalType: m.originalType, opId: m.opId });
      }
    } else if (m?.t === 'result') {
      result.textContent = JSON.stringify(m.value, null, 2);
      status.textContent = 'done';
    }
  });

  // View call button
  document.getElementById('callBtn')!.addEventListener('click', async () => {
    const rpcUrl = (document.getElementById('rpcUrl') as HTMLInputElement).value;
    const contractId = (document.getElementById('contractId') as HTMLInputElement).value;
    const methodName = (document.getElementById('methodName') as HTMLInputElement).value;
    const argsText = (document.getElementById('args') as HTMLInputElement).value;
    let args: any = {};
    try { args = argsText ? JSON.parse(argsText) : {}; } catch {}
    await ch.send({ t: 'view-call', rpcUrl, contractId, methodName, args });
    status.textContent = '📖 calling view method...';
  });

  // Sign & send button
  document.getElementById('signBtn')!.addEventListener('click', async () => {
    const rpcUrl = (document.getElementById('rpcUrl') as HTMLInputElement).value;
    const signerId = (document.getElementById('signerId') as HTMLInputElement).value;
    const receiverId = (document.getElementById('receiverId') as HTMLInputElement).value;
    const methodName = (document.getElementById('txMethodName') as HTMLInputElement).value;
    const argsText = (document.getElementById('txArgs') as HTMLInputElement).value;
    const gas = (document.getElementById('gas') as HTMLInputElement).value;
    const deposit = (document.getElementById('deposit') as HTMLInputElement).value;
    const privateKey = (document.getElementById('privateKey') as HTMLInputElement).value;

    if (!signerId || !receiverId || !methodName || !privateKey) {
      status.textContent = '❌ Please fill all required fields';
      return;
    }

    let args: any = {};
    try { args = argsText ? JSON.parse(argsText) : {}; } catch (e) {
      status.textContent = '❌ Invalid JSON args';
      return;
    }

    await ch.send({ t: 'sign-and-send', rpcUrl, signerId, receiverId, methodName, args, gas, deposit, privateKey });
    status.textContent = '✍️ signing and sending transaction...';
  });
})();
