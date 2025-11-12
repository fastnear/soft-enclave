import { enclaveHandleHello } from '../libs/secure-channel.js';
import {
  makeViewFunctionRequest,
  makeAccessKeyRequest,
  makeBlockRequest,
  makeSendTransactionRequest,
  createFunctionCallTransaction,
  signTransaction,
  encodePublicKey,
  derivePublicKey,
  parsePrivateKey
} from '@fastnear/soft-enclave-near';

const expectedParent = (window as any).PARENT_ORIGIN ?? 'http://localhost:5173';

const log = (m: string) => { document.getElementById('log')!.innerHTML += m + '<br/>'; };

// Track pending sign operations by request ID
const pendingSignOps = new Map<string, { params: any; accessKeyNonce?: string; blockHash?: string }>();

enclaveHandleHello(expectedParent, (chan) => {
  log('channel: ready');
  chan.onmessage(async (m: any) => {
    if (m?.t === 'view-call') {
      const { url, req } = makeViewFunctionRequest({
        rpcUrl: m.rpcUrl,
        contractId: m.contractId,
        methodName: m.methodName,
        args: m.args,
        finality: 'optimistic'
      });
      await chan.send({ t: 'egress-request', url, req, originalType: 'view-call' });
    }
    else if (m?.t === 'sign-and-send') {
      // Step 1: Derive public key from private key
      const privateKeyBytes = parsePrivateKey(m.privateKey);
      const publicKeyBytes = derivePublicKey(privateKeyBytes);
      const publicKey = encodePublicKey(publicKeyBytes);

      log(`Sign & Send: ${m.signerId} → ${m.receiverId}.${m.methodName}()`);

      // Store operation details
      const opId = crypto.randomUUID();
      pendingSignOps.set(opId, { params: m });

      // Step 2: Fetch access key to get nonce and verify permissions
      const { url: akUrl, req: akReq } = makeAccessKeyRequest({
        rpcUrl: m.rpcUrl,
        accountId: m.signerId,
        publicKey: publicKey
      });
      await chan.send({ t: 'egress-request', url: akUrl, req: akReq, originalType: 'sign-and-send-access-key', opId });
    }
    else if (m?.t === 'egress-response') {
      if (m.ok) {
        const value = m.resp?.result ?? m.resp;

        // Handle different response types
        if (m.originalType === 'view-call') {
          await chan.send({ t: 'result', value });
          (document.getElementById('out')!).textContent = JSON.stringify(value, null, 2);
        }
        else if (m.originalType === 'sign-and-send-access-key') {
          // Got access key response, now fetch block hash
          const op = pendingSignOps.get(m.opId);
          if (!op) return;

          const accessKey = value;
          const nonce = String(BigInt(accessKey.nonce) + 1n);
          op.accessKeyNonce = nonce;

          // Check permissions (if FunctionCall permission)
          if (accessKey.permission && accessKey.permission.FunctionCall) {
            const perm = accessKey.permission.FunctionCall;
            if (perm.receiver_id !== op.params.receiverId) {
              await chan.send({ t: 'result', value: { error: `Access key not allowed for receiver: ${op.params.receiverId}` } });
              pendingSignOps.delete(m.opId);
              return;
            }
            if (perm.method_names && perm.method_names.length > 0 && !perm.method_names.includes(op.params.methodName)) {
              await chan.send({ t: 'result', value: { error: `Access key not allowed for method: ${op.params.methodName}` } });
              pendingSignOps.delete(m.opId);
              return;
            }
          }

          log(`Access key OK, nonce: ${nonce}`);

          // Fetch recent block for block hash
          const { url: blockUrl, req: blockReq } = makeBlockRequest({
            rpcUrl: op.params.rpcUrl,
            finality: 'final'
          });
          await chan.send({ t: 'egress-request', url: blockUrl, req: blockReq, originalType: 'sign-and-send-block', opId: m.opId });
        }
        else if (m.originalType === 'sign-and-send-block') {
          // Got block hash, now sign and send transaction
          const op = pendingSignOps.get(m.opId);
          if (!op) return;

          const block = value;
          const blockHash = block.header.hash;
          op.blockHash = blockHash;

          log(`Block hash: ${blockHash.slice(0, 12)}...`);

          // Create transaction
          const tx = createFunctionCallTransaction({
            signerId: op.params.signerId,
            receiverId: op.params.receiverId,
            methodName: op.params.methodName,
            args: op.params.args,
            gas: op.params.gas,
            deposit: op.params.deposit,
            nonce: op.accessKeyNonce!,
            blockHash: blockHash
          });

          // Sign transaction (private key only exposed during this operation)
          const signedTx = await signTransaction(tx, op.params.privateKey);

          // Encode signed transaction as base64
          const txJson = JSON.stringify({
            transaction: signedTx.transaction,
            signature: signedTx.signature
          });
          const signedTxBase64 = btoa(txJson);

          log(`Signed tx: ${signedTx.hash.slice(0, 12)}...`);

          // Send transaction
          const { url: sendUrl, req: sendReq } = makeSendTransactionRequest({
            rpcUrl: op.params.rpcUrl,
            signedTransaction: signedTxBase64
          });
          await chan.send({ t: 'egress-request', url: sendUrl, req: sendReq, originalType: 'sign-and-send-result', opId: m.opId });
        }
        else if (m.originalType === 'sign-and-send-result') {
          // Transaction sent!
          const op = pendingSignOps.get(m.opId);
          if (op) pendingSignOps.delete(m.opId);

          log(`TX sent: ${JSON.stringify(value)}`);
          await chan.send({ t: 'result', value });
          (document.getElementById('out')!).textContent = JSON.stringify(value, null, 2);
        }
      } else {
        await chan.send({ t: 'result', value: { error: m.error } });
        (document.getElementById('out')!).textContent = String(m.error);

        // Clean up pending operation on error
        if (m.opId) {
          pendingSignOps.delete(m.opId);
        }
      }
    }
  });
});
