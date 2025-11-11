type Bytes = Uint8Array;
const te = new TextEncoder();
const td = new TextDecoder();

async function importPubKey(raw: Bytes) {
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
}
async function exportPubKey(k: CryptoKey) {
  const raw = await crypto.subtle.exportKey("raw", k);
  return new Uint8Array(raw);
}

async function hkdfKey(ikm: ArrayBuffer, salt: Bytes, info: string, usages: KeyUsage[]) {
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: te.encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

export type Channel = {
  id: string;
  send: (msg: any) => Promise<void>;
  onmessage: (fn: (msg: any) => void) => void;
  close: () => void;
};

export async function createHostChannel(iframe: HTMLIFrameElement, targetOrigin: string): Promise<Channel> {
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const hostPub = await exportPubKey(kp.publicKey);
  const nonceH = crypto.getRandomValues(new Uint8Array(16));
  const id = crypto.randomUUID();
  const port = iframe.contentWindow!;

  port.postMessage({ t: "hello", id, hostPub: Array.from(hostPub), nonceH: Array.from(nonceH) }, { targetOrigin });

  return await new Promise((resolve) => {
    let txKey: CryptoKey, rxKey: CryptoKey;
    let seqTx = 0, seqRx = 0;
    let onmsg: ((msg: any) => void) | null = null;

    function onCipher(ev: MessageEvent) {
      if (ev.origin !== targetOrigin) return;
      const m = ev.data;
      if (m?.t !== "cipher" || m?.id !== id) return;
      const { seq, iv, ct, aad } = m;
      if (seq !== seqRx) return; // strict monotonic
      crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv), additionalData: te.encode(aad) }, rxKey!, new Uint8Array(ct))
        .then((pt) => {
          if (!pt) return;
          seqRx += 1;
          const payload = JSON.parse(td.decode(new Uint8Array(pt)));
          onmsg?.(payload);
        }).catch(() => {});
    }

    function onHelloResp(ev: MessageEvent) {
      if (ev.origin !== targetOrigin) return;
      const data = ev.data;
      if (data?.t !== "helloResp" || data?.id !== id) return;
      const enclavePub = new Uint8Array(data.enclavePub);
      const nonceE = new Uint8Array(data.nonceE);
      importPubKey(enclavePub).then(async (peerKey) => {
        const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerKey }, kp.privateKey!, 256);
        const salt = new Uint8Array([...nonceH, ...nonceE]);
        txKey = await hkdfKey(bits, salt, "soft-enclave-v1/tx-host->enclave", ["encrypt"]);
        rxKey = await hkdfKey(bits, salt, "soft-enclave-v1/tx-enclave->host", ["decrypt"]);
        window.addEventListener("message", onCipher);
        resolve({
          id,
          send: async (x: any) => {
            const aad = `id=${id};dir=host->enclave;seq=${seqTx}`;
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const pt = new TextEncoder().encode(JSON.stringify(x));
            const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, txKey!, pt);
            port.postMessage({ t: "cipher", id, seq: seqTx++, iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)), aad }, { targetOrigin });
          },
          onmessage: (fn) => { onmsg = fn; },
          close: () => { window.removeEventListener("message", onCipher); window.removeEventListener("message", onHelloResp as any); }
        });
      });
    }

    window.addEventListener("message", onHelloResp);
  });
}

export async function enclaveHandleHello(expectedParent: string, onReady: (chan: Channel) => void) {
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const enclavePub = await exportPubKey(kp.publicKey);
  const nonceE = crypto.getRandomValues(new Uint8Array(16));
  let txKey: CryptoKey, rxKey: CryptoKey;
  let seqTx = 0, seqRx = 0;
  let id = "";
  let onmsg: ((msg: any) => void) | null = null;

  function onCipher(ev: MessageEvent) {
    if (ev.origin !== expectedParent) return;
    const m = ev.data;
    if (m?.t !== "cipher" || m?.id !== id) return;
    const { seq, iv, ct, aad } = m;
    if (seq !== seqRx) return;
    crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(iv), additionalData: new TextEncoder().encode(aad) }, rxKey!, new Uint8Array(ct))
      .then((pt) => {
        if (!pt) return;
        seqRx += 1;
        const payload = JSON.parse(new TextDecoder().decode(new Uint8Array(pt)));
        onmsg?.(payload);
      }).catch(() => {});
  }

  function onHello(ev: MessageEvent) {
    if (ev.origin !== expectedParent) return;
    const data = ev.data;
    if (data?.t !== "hello") return;
    id = data.id;
    const hostPub = new Uint8Array(data.hostPub);
    const nonceH = new Uint8Array(data.nonceH);
    importPubKey(hostPub).then(async (peerKey) => {
      const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerKey }, kp.privateKey!, 256);
      const salt = new Uint8Array([...nonceH, ...nonceE]);
      txKey = await hkdfKey(bits, salt, "soft-enclave-v1/tx-enclave->host", ["encrypt"]);
      rxKey = await hkdfKey(bits, salt, "soft-enclave-v1/tx-host->enclave", ["decrypt"]);
      (ev.source as WindowProxy).postMessage({ t: "helloResp", id, enclavePub: Array.from(enclavePub), nonceE: Array.from(nonceE) }, { targetOrigin: expectedParent });
      window.addEventListener("message", onCipher);
      const chan: Channel = {
        id,
        send: async (x: any) => {
          const aad = `id=${id};dir=enclave->host;seq=${seqTx}`;
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const pt = new TextEncoder().encode(JSON.stringify(x));
          const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, txKey!, pt);
          (ev.source as WindowProxy).postMessage({ t: "cipher", id, seq: seqTx++, iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)), aad }, { targetOrigin: expectedParent });
        },
        onmessage: (fn) => { onmsg = fn; },
        close: () => { window.removeEventListener("message", onCipher); window.removeEventListener("message", onHello as any); }
      };
      onReady(chan);
    });
  }

  window.addEventListener("message", onHello);
}
