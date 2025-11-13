# Soft Enclave (Browser) — Definition of Done (v0.1)

**Scope (v0.1):**
- Core export: browser-based soft enclave (cross-origin iframe) with encrypted host↔enclave channel.
- Guarded egress: allowlisted NEAR RPC `query` (view calls), `block`, `send_tx`, `broadcast_tx_commit`.
- NEAR adapter for both view calls AND transaction signing.
- Hardened enclave origin via server headers.
- ✅ **Tx signing INCLUDED in v0.1** (gate switched on!)

---

## Run / Build

- [x] `npm install` completes without audit blockers of severity `high`+ in runtime deps.
- [x] `yarn dev:iframe` brings up:
  - Host on `http://localhost:3000` (Vite dev server)
  - Enclave on `http://localhost:3010` (iframe backend, port = host + 10)
- [x] Build process documented: `yarn build` required before first run
- [x] iframe backend routes configured: boot.html, egress-assert.js, enclave-main.js, crypto-protocol.js, quickjs-runtime.js
- [x] QuickJS vendor files accessible: /vendor/quickjs-emscripten.mjs and dependencies
- [ ] Example loads: `examples/near-soft-enclave/host/index.html`
- [ ] View call succeeds against a public testnet contract.
- [ ] Transaction signing succeeds against a public testnet contract.

---

## Enclave Origin Hardening (must be HTTP headers)

- [x] Enclave server sets:
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Embedder-Policy: require-corp`
  - `Content-Security-Policy: default-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`
- [x] Host does **not** inject cookies or credentials to enclave; `fetch` uses `credentials: 'omit'`.
- [x] Enclave HTML may keep `<meta http-equiv>` for local preview, but headers are the source of truth.

---

## Host↔Enclave Channel

- [x] ECDH P‑256 handshake (WebCrypto).
- [x] HKDF‑SHA256 derives **directional** AES‑GCM keys:
  - labels: `soft-enclave-v1/tx-host->enclave`, `soft-enclave-v1/tx-enclave->host`
- [x] AAD binds `{id, direction, seq}`.
- [x] Strict `origin` checks on `postMessage`.
- [x] Monotonic sequence; out‑of‑order drops; IVs are random per message.

---

## Guarded Egress

- [x] Policy allowlist of **hosts** (e.g., `rpc.testnet.near.org`) and **methods** (v0.1: `query`, `block`, `send_tx`, `broadcast_tx_commit`).
- [x] Request cap (`maxReqBytes`) and response cap (`maxRespBytes`) enforced.
- [x] HTTPS enforced except for `localhost`.
- [x] `fetch` uses `mode: 'cors'`, `credentials: 'omit'`, `redirect: 'error'`, `referrerPolicy: 'no-referrer'`.
- [ ] Guard rejects any method/host not in policy (verified by a negative test).

---

## NEAR (View + Sign)

- [x] Enclave builds `query { request_type: "call_function" }` with **UTF‑8 → base64** args.
- [x] Host relays via guard; only `result` is re-exposed to host UI.
- [x] Example UI defaults to testnet RPC + a trivial view method.

---

## API / Packages

- [x] Public exports documented:
  - `packages/near/src/enclave/near-enclave.ts`: `makeViewFunctionRequest(...)`, `makeAccessKeyRequest(...)`, `makeBlockRequest(...)`, `makeSendTransactionRequest(...)`
  - `packages/near/src/enclave/near-tx.ts`: `signTransaction(...)`, `createFunctionCallTransaction(...)`, `createTransferTransaction(...)`
  - `packages/near/src/host/rpc.ts`: `makeEgressGuard(...)`
- [x] No unstable internal paths are required by the example.

---

## Tests (minimum)

- [ ] Channel unit test: rejects wrong `origin`, wrong `seq`, or tampered AAD.
- [ ] Guard unit test: denies unknown host; denies unknown method; allows `query` to allowlisted host.
- [ ] Example smoke: view call returns non-empty `result` for a known public contract.
- [ ] Example smoke: transaction signing returns tx hash for a known testnet account.

---

## Docs

- [ ] `README.md`: quickstart (two origins), link to example.
- [ ] `docs/THREAT_MODEL.md`: plaintext egress is impossible when guard is active; replay/seq/AAD rationale.
- [ ] `docs/NEAR_INTEGRATION_NOTES.md`: phases; view calls AND tx signing in v0.1.

---

## ✅ Tx Signing Gate (SWITCHED ON for v0.1!)

- [x] Enclave builds & **signs** Ed25519 tx (using tweetnacl from `ed25519:<base58 64B>`).
- [x] Access‑key fetch (`view_access_key`) enforces FunctionCall permission (receiver/methods).
- [x] Host policy allows `send_tx` (and `broadcast_tx_commit` fallback).
- [x] UI path: "Sign & Send" separated from view; clear gas/deposit units.

---

## Release / Hygiene

- [x] `yarn build` succeeds; all 6 packages build cleanly.
- [x] `yarn type-check` passes.
- [ ] Licenses of included deps recorded.
- [ ] Tag: `v0.1.0` (view + signing). Changelog lists future enhancements.
