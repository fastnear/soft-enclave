Here you go — an ARCHITECTURE.md you can drop straight into the repo.

# Soft Enclave Architecture

## 0. Purpose

This repository implements a **browser “soft enclave”**:

- A **host app** on one origin (`http://localhost:3000`).
- An **enclave iframe** on a separate origin (`http://localhost:3010`).
- Inside the enclave: **QuickJS compiled to WebAssembly**, NEAR signing helpers, and optional sealed storage.
- Between them: an **encrypted, sequence-checked message channel** and a **guarded egress** path to NEAR RPC.

The goal is to provide a **practical, web-native enclave**:
- Stronger than `localStorage` / `sessionStorage` (no raw secrets in host origin).
- Without requiring hardware TEEs or native platform support.
- Demonstrated via an interactive demo (execute untrusted JS, sign NEAR transactions, inspect security metrics).

---

## 1. High-Level Overview

### 1.1 Components

**Host app (`localhost:3000`)**

- Built with Vite (see `vite.config.js`).
- Serves the demo UI (`demo/`) and owns the *host half* of the enclave protocol.
- Creates and controls the enclave iframe.
- Provides UI-level switches:
  - “Initialize Enclave”
  - “Execute Code”
  - “Try Malicious Code”
  - “Sign Transaction”
  - “Zero Memory After Execution” toggle

**Enclave app (`localhost:3010`)**

- Served by `enclave-server.js`.
- Hosts:
  - `boot.html` (entry HTML)
  - `contentScripts.bundle.js` + `.wasm` (QuickJS Emscripten glue)
  - `boot.bundle.js` (bundled enclave logic)
- Implements the enclave side of the protocol:
  - QuickJS runtime
  - Signing helpers
  - Optional sealed storage

**NEAR RPC**

- External NEAR RPC endpoints (`rpc.testnet.near.org`, `rpc.mainnet.near.org`, etc.).
- Only reachable through a **policy-enforced egress guard** on the host side.

---

### 1.2 Security Envelope

**Host headers**

- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Content-Security-Policy` (CSP), including:
  - `default-src 'self'`
  - `frame-src 'self' http://localhost:3010`
  - `child-src 'self' http://localhost:3010`
  - `connect-src 'self' https://rpc.testnet.near.org https://rpc.mainnet.near.org`
  - `script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval' blob:`
  - `base-uri 'none'`, `form-action 'none'`, `object-src 'none'`

**Enclave headers**

- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Resource-Policy: cross-origin`
- `Content-Security-Policy`:
  - `default-src 'self'`
  - `script-src 'self' 'wasm-unsafe-eval'`
  - `connect-src 'self'`
  - `frame-ancestors http://localhost:3000`
  - `base-uri 'none'`, `form-action 'none'`, `object-src 'none'`

Result: the enclave lives in a **cross-origin isolated** context, embedded only by the host, with a minimal resource surface.

---

## 2. Message Flow & Protocol

### 2.1 Handshake: host ↔ enclave

1. **Enclave boot (`boot.html` + `boot.bundle.js`)**
   - On load, the enclave announces readiness:

     ```ts
     window.parent.postMessage(
       { t: 'ready', version: 'soft-enclave:v0.1', enclaveOrigin: location.origin },
       hostOrigin // derived from document.referrer or '*'
     );
     ```

2. **Host listens and connects**
   - Host receives `{ t: 'ready' }` from `http://localhost:3010`.
   - Creates a `MessageChannel`:

     ```ts
     const channel = new MessageChannel();
     iframe.contentWindow!.postMessage({ t: 'connect' }, enclaveOrigin, [channel.port2]);
     const port = channel.port1;
     ```

3. **Enclave binds the port**
   - Enclave receives `{ t: 'connect' }`, grabs `ev.ports[0]`, and sets:

     ```ts
     port.onmessage = onPortMessage;
     port.start?.();
     port.postMessage({ t: 'connected', version: 'soft-enclave:v0.1' });
     ```

From then on, all host↔enclave traffic goes over this `MessagePort`.

> Note: The actual production demo wraps this protocol with an ECDH + AES-GCM layer (sequence numbers, AAD, etc.). For architectural purposes, you can think of it as a typed RPC over a secure channel.

---

### 2.2 RPC surface (conceptual)

**Host → Enclave**

- Initialize:
  ```ts
  { t: 'init', id, sessionId }

  •  Evaluate code:

{ t: 'eval', id, code, timeoutMs, zeroMemory }


  •  Sign NEAR transaction:

{
  t: 'sign',
  id,
  rpcUrl,
  signerId,
  receiverId,
  methodName,
  args,
  gasTgas,
  depositNear
}



Enclave → Host
  •  Init ok:

{ t: 'init:ok', id }


  •  Eval result:

{ t: 'eval:ok', id, value, durationMs, memoryZeroed, keyExposureMs }
{ t: 'eval:err', id, error, durationMs, memoryZeroed, keyExposureMs }


  •  Sign result:

{ t: 'sign:ok', id, txHash, rpcResult }
{ t: 'sign:err', id, error }



⸻

3. QuickJS Runtime & Sandboxing

3.1 QuickJS instantiation

The enclave uses QuickJS via quickjs-emscripten:
  •  Factory: getQuickJS() from the NPM package.
  •  VM creation:

let QuickJSMod: any;
let vm: any;

async function getVm() {
  if (!QuickJSMod) QuickJSMod = await getQuickJS();
  if (!vm) vm = QuickJSMod.createVm();
  return vm;
}



VM is intentionally reused between calls to support persistence testing (see zeroMemory below).

3.2 Code wrapping

User-provided code is never passed raw into QuickJS. It is wrapped:

function wrapUserCode(code: string): string {
  return [
    '(function(){',
    '"use strict";',
    code,
    '})()'
  ].join('\n');
}

  •  Allows top-level return in demo snippets.
  •  Keeps user code in a strict, function-local scope.
  •  Makes the behavior independent of QuickJS’s module vs script semantics.

3.3 Eval semantics & toggle (zeroMemory)

Main entry: evalQuickJS(code: string, opts: { zeroMemory?: boolean }).
  1.  Resolve / create the VM: const vm = await getVm().
  2.  Wrap code: const wrapped = wrapUserCode(code).
  3.  Evaluate: const res = vm.evalCode(wrapped).
  4.  Dump value:
  •  On success: result = vm.dump(res.value).
  •  On error: error = String(vm.dump(res.error)).
  5.  Respect zeroMemory:
  •  zeroMemory === true:
  •  Dispose handles where appropriate.
  •  vm.dispose() and set vm = null.
  •  Set memoryZeroed: true in the result.
  •  zeroMemory === false:
  •  Keep VM and its state.
  •  Set memoryZeroed: false.

This creates two modes:
  •  Stateless mode: full zeroization after each run.
  •  Persistent mode: VM state (e.g., globalThis) survives across executions.

The demo UI’s “Memory Zeroed” line is derived from this flag.

⸻

4. NEAR Transaction Signing

4.1 High-level flow
  1.  Host collects inputs from UI:
  •  signerId, receiverId, methodName, args, gasTgas, depositNear.
  •  A signing key (demo-level; in a production app this would be handled by a secure vault or derived per session).
  2.  Host sends sign request to enclave via the channel.
  3.  Enclave performs NEAR-specific steps:
  •  Access key fetch:

{
  "jsonrpc": "2.0",
  "id": "ak",
  "method": "query",
  "params": {
    "request_type": "view_access_key",
    "finality": "final",
    "account_id": "<signer>",
    "public_key": "ed25519:..."
  }
}

  •  Extracts nonce and uses nonce + 1.

  •  Block hash fetch:

{
  "jsonrpc": "2.0",
  "id": "bh",
  "method": "block",
  "params": { "finality": "final" }
}

  •  Base58-decodes result.header.hash to a 32-byte Uint8Array.
  •  Validates length (32 bytes) to avoid malformed inputs.

  •  Transaction construction:
  •  Builds a FunctionCall transaction.
  •  Leverages existing near-tx serializer (Borsh-encoded).
  •  Signing (inside enclave):
  •  Uses tweetnacl.sign.detached(message, secretKey).
  •  secretKey and publicKey never leave the enclave origin.
  •  RPC call:
  •  Encodes signed_tx_base64 (tx + signature).
  •  Sends send_tx request:

{
  "jsonrpc": "2.0",
  "id": "send",
  "method": "send_tx",
  "params": { "signed_tx_base64": "..." }
}


  4.  Host egress guard vets the request (see below) and performs the RPC.
  5.  Enclave returns result / error back to host for display.

4.2 Egress guard

Host-side guard is the only component allowed to hit NEAR RPC. It enforces:
  •  Host allowlist: e.g. rpc.testnet.near.org, rpc.mainnet.near.org.
  •  Method allowlist: query, block, send_tx (and optionally broadcast_tx_commit fallback).
  •  Request size caps: maxReqBytes.
  •  Response size caps: maxRespBytes.
  •  HTTPS requirement: HTTPS for non-localhost.

This ensures even if the enclave is compromised, outbound calls are constrained to a narrow NEAR RPC surface.

⸻

5. Tests & Invariants

Key test suites (names may differ slightly):
  •  channel-security.test.ts
  •  Confirms:
  •  Strict origin checks on messages.
  •  Monotonic sequence enforcement.
  •  AAD includes id, direction, and seq.
  •  egress-guard.test.ts / egress-guard.https-and-fallback.test.ts
  •  Validates:
  •  Host allowlist behavior.
  •  Method allowlist behavior.
  •  Request/response caps.
  •  HTTPS enforcement with localhost exception.
  •  send_tx → broadcast_tx_commit fallback.
  •  quickjs / deterministic-shims.test.js
  •  Ensures deterministic behavior where required.
  •  Validates that the “zeroMemory” semantics behave as expected.
  •  transaction-signing.test.ts
  •  Ensures:
  •  Correct Borsh layout.
  •  Valid block hash decoding (32 bytes).
  •  Correct nonce handling (nonce + 1).
  •  Ed25519 signatures are formed correctly.
  •  Integration tests (gated by env flags)
  •  Cover end-to-end flows:
  •  Enclave init, code execution, signing with live dev servers.

⸻

6. Why This Is Better Than localStorage

Compared to typical front-end storage patterns:
  •  Origin isolation:
  •  Secrets and execution live in a tightly controlled iframe origin with its own CSP, COEP, CORP.
  •  Host-side XSS cannot trivially read enclave state; it must go through the protocol.
  •  Key handling:
  •  Keys are generated/imported inside the enclave origin and kept non-extractable.
  •  Wiping is explicit and testable (zeroMemory), rather than incidental.
  •  Network policy:
  •  All egress is funneled through an audited, parameter-checked guard.
  •  No accidental requests to arbitrary third-party endpoints via compromised code.
  •  Programmable policy:
  •  QuickJS can enforce arbitrary logic about which operations are allowed and under what conditions.
  •  You can embed policy alongside the secrets, not just data.

For “small but high-value” secrets (session tokens, signing keys, policy blobs), this is a strictly stronger model than sprinkling values into localStorage or an in-memory singleton on the host page.

⸻

7. Alpha Scope Summary

For alpha, the parts that matter most:
  •  Cross-origin iframe with:
  •  Correct COOP/COEP/CSP headers.
  •  Deterministic QuickJS loading and Wasm instantiation.
  •  Encrypted message channel with:
  •  Strict origin and sequence checks.
  •  Clear RPC vocabulary (init, eval, sign).
  •  QuickJS runtime with:
  •  Function/IIFE wrapping so demo code runs correctly.
  •  zeroMemory semantics for persistence vs wipe.
  •  NEAR signing path with:
  •  Access key + block hash fetching.
  •  Correct Borsh encoding.
  •  Guarded RPC egress.

Everything else (alternative HPKE, additional demos) is explicitly considered non-blocking and can be iterated on post-alpha of `soft-enclave`.

