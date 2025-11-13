import {
  genECDH, exportRaw, importRaw, deriveSession,
  seal, open, serializePayload, deserializePayload
} from './crypto-protocol.js';

export class EnclaveClient {
  enclaveOrigin: string;
  iframe: HTMLIFrameElement | null;
  port: MessagePort | null;
  session: any;
  seq: number;
  _pending: any;
  _lastSent: any;

  constructor(enclaveOrigin: string) {
    this.enclaveOrigin = enclaveOrigin;
    this.iframe = null;
    this.port = null;
    this.session = null;
    this.seq = 1;
    this._pending = null;
    this._lastSent = null;
    this._onMsg = this._onMsg.bind(this);
  }

  async boot({ codeHashOverride }: { codeHashOverride?: string } = {}) {
    console.log('🔵 [EnclaveClient] boot() called, enclaveOrigin:', this.enclaveOrigin);

    this.iframe = document.createElement('iframe');
    this.iframe.src = `${this.enclaveOrigin}/boot.html`;
    this.iframe.style.display = 'none';
    // Security attributes for cross-origin isolation
    this.iframe.setAttribute('allow', 'cross-origin-isolated');
    // Allow referrer so enclave can verify parent origin
    this.iframe.setAttribute('referrerpolicy', 'strict-origin-when-cross-origin');
    document.body.appendChild(this.iframe);
    console.log('🔵 [EnclaveClient] iframe created and appended, src:', this.iframe.src);

    const { port1, port2 } = new MessageChannel();
    this.port = port1;
    this.port.onmessage = this._onMsg;
    console.log('🔵 [EnclaveClient] MessageChannel created');

    console.log('🔵 [EnclaveClient] Waiting for enclave-ready message...');
    const ready: any = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        console.error('❌ [EnclaveClient] Timeout waiting for enclave-ready message!');
        reject(new Error('Timeout waiting for enclave-ready'));
      }, 10000);

      const onReady = (ev: MessageEvent) => {
        console.log('🔵 [EnclaveClient] Received message:', {
          origin: ev.origin,
          source: ev.source === this.iframe!.contentWindow ? 'iframe' : 'other',
          type: ev.data?.type,
          data: ev.data
        });

        if (ev.source !== this.iframe!.contentWindow) {
          console.log('🔵 [EnclaveClient] Ignoring message: source mismatch');
          return;
        }
        if (ev.origin !== this.enclaveOrigin) {
          console.log('🔵 [EnclaveClient] Ignoring message: origin mismatch', ev.origin, '!==', this.enclaveOrigin);
          return;
        }
        if (ev.data?.type !== 'enclave-ready') {
          console.log('🔵 [EnclaveClient] Ignoring message: type mismatch', ev.data?.type);
          return;
        }

        clearTimeout(timeout);
        window.removeEventListener('message', onReady);
        console.log('✅ [EnclaveClient] Received enclave-ready message!', ev.data);
        resolve(ev.data);
      };

      window.addEventListener('message', onReady);
      this.iframe!.addEventListener('load', () => {
        console.log('🔵 [EnclaveClient] iframe loaded, sending connect message...');
        this.iframe!.contentWindow!.postMessage({ type: 'connect' }, this.enclaveOrigin, [port2]);
        console.log('🔵 [EnclaveClient] connect message sent with port2');
      });
    });

    console.log('🔵 [EnclaveClient] Deriving session keys...');
    const enclavePub = await importRaw(new Uint8Array(ready.enclavePubKey));
    const hostKeys = await genECDH();
    const hostPubRaw = await exportRaw(hostKeys.publicKey);

    const ctx = {
      hostOrigin: location.origin,
      enclaveOrigin: this.enclaveOrigin,
      codeHash: codeHashOverride ?? ready.codeHash
    };
    this.session = await deriveSession(hostKeys.privateKey, enclavePub, ctx);
    this.seq = 1;

    console.log('🔵 [EnclaveClient] Session derived, sending host-hello...');
    this.port.postMessage({ type: 'host-hello', hostPubKey: Array.from(hostPubRaw) });
    console.log('✅ [EnclaveClient] boot() complete!');
  }

  _onMsg(ev: MessageEvent) {
    if (!this._pending) return;
    const { resolve, reject, aad } = this._pending;
    const d = ev.data || {};
    if (d.type === 'ciphertext-result') {
      open(this.session.aeadKey, deserializePayload(d.payload), aad)
        .then(res => { this._pending = null; resolve(res); })
        .catch(err => { this._pending = null; reject(err); });
    } else if (d.type === 'error') {
      this._pending = null;
      reject(new Error(d.error));
    }
  }

  async send(op: string, body: any, aad: string) {
    if (!this.session) throw new Error('no-session');
    const payload = await seal(this.session.aeadKey, this.session.baseIV, this.seq++, { op, ...body }, aad);
    const serialized = serializePayload(payload);
    this._lastSent = serialized;
    this.port!.postMessage({ type: 'ciphertext-call', payload: serialized, seq: this.seq - 1 });
    return await new Promise((resolve, reject) => {
      this._pending = { resolve, reject, aad: `${aad}:result` };
      setTimeout(() => {
        if (this._pending) { this._pending = null; reject(new Error('timeout')); }
      }, 15000);
    });
  }

  lastPayload() { return this._lastSent; }
  resendRaw(serialized: any) { this.port!.postMessage({ type: 'ciphertext-call', payload: serialized, seq: 999999 }); }
}
