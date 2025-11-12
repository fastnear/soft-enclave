import {
  genECDH, exportRaw, importRaw, deriveSession,
  seal, open, serializePayload, deserializePayload
} from './crypto-protocol.js';
import { createQuickJS } from './quickjs-runtime.js';

const EXPECTED_PARENT = new URL(document.referrer || 'http://localhost:8080').origin;
document.body.innerHTML = `<div style="padding: 20px; font-family: monospace;">
  <h2 style="color: green;">✓ Enclave Loaded</h2>
  <p>Expected parent: <code>${EXPECTED_PARENT}</code></p>
  <p>Status: <span id="status">Waiting for parent...</span></p>
</div>`;

let port: MessagePort | null = null;
let session: any = null;
let seqSend = 1;

const seen = new Set<string>(); const fifo: string[] = []; const MAX = 4096;
function rememberIV(iv: Uint8Array) {
  const k = Array.from(iv).map((b: number) => b.toString(16).padStart(2,'0')).join('');
  if (seen.has(k)) return false;
  seen.add(k); fifo.push(k);
  if (fifo.length > MAX) { const old = fifo.shift(); seen.delete(old!); }
  return true;
}

function postToParent(type: string, data: any) {
  window.parent.postMessage({ type, ...data }, EXPECTED_PARENT);
}

function guardedPost(msg: any) {
  port!.postMessage(msg);
}

(async function main(){
  console.log('🟢 [Enclave] main() started');
  console.log('🟢 [Enclave] Expected parent origin:', EXPECTED_PARENT);
  console.log('🟢 [Enclave] Enclave origin:', location.origin);

  console.log('🟢 [Enclave] Waiting for connect message...');
  await new Promise<void>(resolve => {
    const onMessage = (ev: MessageEvent) => {
      console.log('🟢 [Enclave] Received message:', {
        origin: ev.origin,
        expectedOrigin: EXPECTED_PARENT,
        type: ev.data?.type,
        hasPorts: !!ev.ports?.[0]
      });

      if (ev.origin !== EXPECTED_PARENT) {
        console.log('🟢 [Enclave] Ignoring message: origin mismatch');
        return;
      }
      if (ev.data?.type === 'connect' && ev.ports?.[0]) {
        console.log('✅ [Enclave] Received connect message with port!');
        window.removeEventListener('message', onMessage);
        port = ev.ports[0];
        port.start();
        resolve();
      }
    };
    window.addEventListener('message', onMessage);
  });

  console.log('🟢 [Enclave] Creating QuickJS...');
  const qjs = await createQuickJS();
  console.log('✅ [Enclave] QuickJS created');

  console.log('🟢 [Enclave] Generating ECDH keys...');
  const keys = await genECDH();
  const enclavePub = await exportRaw(keys.publicKey);
  const codeHash = 'soft-enclave-demo-v1';
  console.log('✅ [Enclave] ECDH keys generated');

  console.log('🟢 [Enclave] Posting enclave-ready to parent...');
  postToParent('enclave-ready', { enclavePubKey: Array.from(enclavePub), codeHash });
  console.log('✅ [Enclave] enclave-ready posted');

  port!.onmessage = async (evt) => {
    const msg = evt.data || {};
    console.log('🟢 [Enclave] Received port message:', msg.type);

    try {
      if (msg.type === 'host-hello') {
        console.log('🟢 [Enclave] Processing host-hello...');
        const hostPub = await importRaw(new Uint8Array(msg.hostPubKey));
        session = await deriveSession(keys.privateKey, hostPub, {
          hostOrigin: EXPECTED_PARENT,
          enclaveOrigin: location.origin,
          codeHash
        });
        console.log('✅ [Enclave] Session established!');
        return;
      }

      if (msg.type === 'ciphertext-call') {
        if (!session) throw new Error('session-not-established');
        const payload = deserializePayload(msg.payload);

        if (!rememberIV(payload.iv)) throw new Error('replay-detected');

        const call: any = await open(session.aeadKey, payload, 'op=evalQuickJS');
        if (call.op === 'evalQuickJS') {
          const out = qjs.evalQuickJS(call.code);
          const ct = await seal(session.aeadKey, session.baseIV, seqSend++, out, 'op=evalQuickJS:result');
          guardedPost({ type:'ciphertext-result', payload: serializePayload(ct), seq: seqSend - 1 });
          return;
        }
        if (call.op === 'test_egress_violation') {
          try {
            port!.postMessage({ type:'not-allowed-plaintext', value: 1 });
            guardedPost({ type:'error', error:'egress-guard-did-not-trigger' });
          } catch(e) {
            guardedPost({ type:'error', error:String(e) });
          }
          return;
        }

        throw new Error('unsupported-op');
      }

      throw new Error('unsupported-message');
    } catch (e) {
      guardedPost({ type:'error', error:String(e) });
    }
  };
})();
