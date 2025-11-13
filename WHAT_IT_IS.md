# What this thing is

This repo is a browser “soft enclave”:
  •  A host app on one origin (localhost:3000)
  •  An enclave iframe on another origin (localhost:3010)
  •  Inside the enclave: QuickJS compiled to Wasm, plus a small runtime and storage layer
  •  Between them: a single encrypted message channel and a guarded egress path to NEAR RPC

The demo page is just a guided tour over that system:
  1.  Initialize Enclave
  2.  Execute untrusted code inside QuickJS
  3.  Sign a NEAR transaction with ephemeral keys
  4.  Display security metrics (key exposure, memory wipe behavior, etc.)

The important bit: it’s strictly stronger than localStorage / sessionStorage and “raw iframe sandboxing” without being a full SGX/TEE. It’s a practical, web-native enclave.

⸻

1. Process architecture

Host side (port 3000)
  •  Built with Vite; serves the demo UI and the host half of the enclave protocol.
  •  Sends all enclave traffic through a MessageChannel bound to the iframe:
  •  No direct postMessage noise, everything goes over port1 / port2.
  •  Applies a strict CSP:
  •  default-src 'self'
  •  frame-src 'self' http://localhost:3010
  •  connect-src 'self' ... (plus NEAR RPCs)
  •  Declares COOP/COEP:
  •  Cross-Origin-Opener-Policy: same-origin
  •  Cross-Origin-Embedder-Policy: require-corp
  •  Populates the UI:
  •  Buttons: “Initialize Enclave”, “Execute Code”, “Try Malicious Code”, “Sign Transaction”
  •  A zeroMemory toggle that controls whether the enclave wipes its QuickJS VM per run.

Enclave side (port 3010)
  •  A tiny HTTP server (enclave-server.js) that:
  •  Serves the enclave HTML (boot.html), the bundled JS (boot.bundle.js), and the QuickJS Wasm glue.
  •  Sends headers:
  •  Cross-Origin-Embedder-Policy: require-corp
  •  Cross-Origin-Resource-Policy: cross-origin
  •  CSP with script-src 'self' 'wasm-unsafe-eval' and frame-ancestors http://localhost:3000
  •  The enclave JS stack:
  1.  QuickJS Emscripten runtime (e.g. contentScripts.bundle.js + .wasm)
  2.  A bundled boot script (boot.bundle.js) that:
  •  Listens for ready / connect handshake from host
  •  Spins up the QuickJS runtime
  •  Implements the enclave RPC handlers (init, eval, signTx, etc.)

Net effect: the iframe is cross-origin, cross-origin isolated, with a very tight CSP, and the only API surface is a message protocol over a MessagePort.

⸻

2. Channel & protocol

Handshake
  1.  Enclave loads boot.html, announces itself:

window.parent.postMessage({ t: 'ready', version, enclaveOrigin: location.origin }, hostOrigin);


  2.  Host listens for { t: 'ready' } from the expected origin, creates a MessageChannel, and replies:

const channel = new MessageChannel();
iframe.contentWindow.postMessage({ t: 'connect' }, enclaveOrigin, [channel.port2]);
const port = channel.port1;


  3.  Enclave receives connect, binds port.onmessage = onPortMessage.

Now host and enclave have a dedicated, origin-checked, full-duplex channel.

Messages

Host → enclave messages (conceptually):
  •  init: { t: 'init', id, sessionId }
  •  eval: { t: 'eval', id, code, timeoutMs, zeroMemory }
  •  sign: { t: 'sign', id, txParams... }

Enclave → host responses:
  •  init:ok: { t: 'init:ok', id }
  •  eval:ok: { t: 'eval:ok', id, value, durationMs, memoryZeroed, keyExposureMs }
  •  eval:err: { t: 'eval:err', id, error, durationMs, memoryZeroed, keyExposureMs }
  •  sign:ok / sign:err

The encryption piece (ECDH + AES-GCM + AAD) wraps this protocol underneath: host and enclave derive keys, then encrypt/decrypt payloads before handing them to their respective RPC handlers. From the demo’s perspective, you just see typed messages and a result.

⸻

3. QuickJS sandbox behavior

The QuickJS runtime is where the “execute untrusted code safely” story lives.

Runtime design
  •  Uses the quickjs-emscripten npm package (no manual vendor paths).
  •  Maintains a singleton VM:

let QuickJSMod: any;
let vm: any;

async function getVm() {
  if (!QuickJSMod) QuickJSMod = await getQuickJS();
  if (!vm) vm = QuickJSMod.createVm();
  return vm;
}


  •  Exposes evalQuickJS(code, { zeroMemory }) which:
  1.  Ensures VM exists (getVm()).
  2.  Wraps user code into an IIFE so top-level return works:

function wrapUserCode(code: string) {
  return [
    '(function(){',
    '"use strict";',
    code,
    '})()'
  ].join('\n');
}


  3.  Calls vm.evalCode(wrapped).
  4.  Dumps the QuickJS value into a normal JS value with vm.dump.
  5.  Computes metrics: totalDurationMs, keyExposureMs.
  6.  Applies zeroMemory semantics (more below).

The zeroMemory toggle

This is the interesting bit.

The demo exposes a UI toggle “Zero Memory After Execution”. That boolean is passed all the way down into evalQuickJS:
  •  When zeroMemory: true:
  •  After running the code, the enclave:
  •  Disposes relevant handles.
  •  Disposes the VM (vm.dispose()).
  •  Sets vm = null so the next eval creates a fresh VM.
  •  Returns memoryZeroed: true.
  •  When zeroMemory: false:
  •  The enclave:
  •  keeps the VM alive.
  •  does not dispose the global state or the VM.
  •  Returns memoryZeroed: false.

This gives you:
  •  A “destroyed enclave” mode (stateless, fully wiped between requests).
  •  A “sticky enclave” mode that keeps internal state (for testing persistence and attack surface).

From a PE perspective, this is a nice way to test the security/performance tradeoff directly in the browser: you can literally see scenarios where state persistence is desirable vs when you want aggressive zeroization.

⸻

4. NEAR transaction signing

The NEAR path is similar in spirit: the enclave is the only place where private keys ever live in plaintext.

Steps
  1.  Host UI collects signing parameters:
  •  signerId, receiverId, methodName, args, gas (TGas), deposit (NEAR).
  •  An ephemeral or derived secret key (demo level; in production you’d use a real key derivation/encrypted vault).
  2.  Host sends a sign request through the encrypted channel:

port.postMessage({
  t: 'sign',
  id,
  rpcUrl,
  signerId,
  receiverId,
  methodName,
  args,
  gasTgas,
  depositNear
});


  3.  Inside the enclave, the NEAR helper:
  •  Fetches the view access key:

{
  "method": "query",
  "params": {
    "request_type": "view_access_key",
    "finality": "final",
    "account_id": "<signer>",
    "public_key": "ed25519:..."
  }
}

and uses nonce + 1.

  •  Fetches a final block hash:

{
  "method": "block",
  "params": { "finality": "final" }
}

and base58-decodes result.header.hash to exactly 32 bytes.

  •  Builds a FunctionCall transaction with correct Borsh encoding (using your near-tx helper).
  •  Signs the hash with Ed25519 via tweetnacl inside the enclave.
  •  Produces signed_tx_base64 and sends a send_tx RPC request:

{
  "method": "send_tx",
  "params": { "signed_tx_base64": "<...>" }
}


  4.  Host egress guard:
  •  Validates:
  •  Host is one of rpc.testnet.near.org, rpc.mainnet.near.org, etc.
  •  Method is allowed: query, block, send_tx (and optionally broadcast_tx_commit for backward compatibility).
  •  Request size is under caps.
  •  Calls the NEAR RPC and sends the response back into the enclave, which then notifies the host UI.

The metrics for signing (especially keyExposureMs) measure the window between “plaintext key in memory” and “key wiped or VM disposed” inside the enclave.

⸻

5. Tests & invariants

From a principal engineer’s view, the test suite encodes the design constraints:
  •  Channel-security tests:
  •  Verify AAD binding: id|dir|seq are all present in AAD.
  •  Monotonic sequence numbers.
  •  Strict origin checks.
  •  Egress-guard tests:
  •  Host allowlist enforcement.
  •  Method allowlist enforcement.
  •  Request/response byte caps.
  •  HTTPS requirement (with localhost carve-out).
  •  send_tx → broadcast_tx_commit fallback when needed.
  •  QuickJS / determinism tests:
  •  No global leakage.
  •  Non-deterministic operations are controlled or mocked in tests.
  •  zeroMemory affects persistence as expected.
  •  Transaction-signing tests:
  •  Borsh structure correctness.
  •  Base58 decoding to 32-byte block hash.
  •  Proper use of nonce + 1.

And a few integration tests (gated) demonstrate that with the two dev servers up, you can click through the full path.

⸻

6. Why this is “better than localStorage”

Compared to localStorage:
  •  Origin isolation:
  •  Secrets live in a different origin (the enclave) with a narrow, audited message surface.
  •  Even if the host page is compromised by XSS, it can’t trivially enumerate enclave storage; it has to go through the policy-enforced protocol.
  •  Key handling:
  •  Crypto keys are non-extractable and live inside Web Crypto / QuickJS memory in the enclave. The host never sees raw key bytes.
  •  Zero-memory mode can aggressively wipe VM state between runs.
  •  Network policy:
  •  The host can only ask the enclave to call certain RPCs, via a guard that enforces host and method allow-lists and size limits.
  •  You can guarantee that no browser extension or third-party script will “piggyback” off the enclave’s privileges without conforming to the protocol.
  •  Programmable policy:
  •  You’re not just storing opaque blobs; you can embed logic (QuickJS) that enforces how data is accessed, when keys are used, and what leaves the enclave.

For certain classes of payloads — session tokens, small wallets, policy blobs, “high-sensitivity but low-volume” secrets — this is a strictly stronger story than localStorage or a vanilla service-worker cache.
