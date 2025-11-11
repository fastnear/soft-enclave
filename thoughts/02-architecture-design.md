# Secure Enclave Architecture Design

## Overview
Design for a browser-based secure enclave using QuickJS-Wasm in a cross-origin worker with encrypted communication.

## Architecture Components

### 1. Host Page (Main Origin)
- Origin: `https://example.com`
- Responsibilities:
  - Instantiate cross-origin iframe/worker
  - Encrypt payloads before sending
  - Decrypt responses from enclave
  - Manage encryption keys
- Does NOT have access to enclave's WebAssembly.Memory

### 2. Enclave Worker/Iframe (Cross-Origin)
- Origin: `https://enclave.example.com` or `https://different-domain.com`
- Responsibilities:
  - Load quickjs-emscripten v0.31.0 directly (cannot receive Module via postMessage)
  - Decrypt incoming encrypted payloads
  - Execute code in QuickJS sandbox
  - Encrypt results before sending back
  - Never expose WebAssembly.Memory to parent
- Security: Same-origin policy prevents host from accessing Memory

### 3. Encrypted Communication Layer
- Protocol: postMessage with end-to-end encryption
- Encryption: Web Crypto API (SubtleCrypto)
  - Algorithm: AES-GCM (authenticated encryption)
  - Key derivation: PBKDF2 or ECDH for key exchange
  - Message format: `{ iv: ArrayBuffer, ciphertext: ArrayBuffer, tag: ArrayBuffer }`

## Security Properties

### What This Achieves
✓ **Memory confidentiality from host**: Host cannot access enclave's Wasm memory due to SOP
✓ **Encrypted communication**: All data in transit is encrypted
✓ **Isolation**: Wasm sandbox provides memory safety
✓ **Authentication**: AES-GCM provides message authentication

### What This Does NOT Achieve
✗ **Hardware TEE**: No attestation, no hardware-backed secrets
✗ **Side-channel protection**: Still vulnerable to timing attacks
✗ **Host compromise resistance**: If host is malicious, it can send malicious code
✗ **DevTools protection**: User can still inspect enclave with browser DevTools

## Implementation Constraints

### Browser Requirements
- Cross-origin isolation headers (if using SharedArrayBuffer):
  ```
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  ```
- Modern browser with Web Crypto API support
- Worker or iframe support

### Key Security Decisions
1. **Worker vs Iframe**: Use dedicated Worker for better isolation
2. **Module Loading**: Load quickjs.wasm via fetch() in worker (cannot postMessage Module)
3. **Key Management**: Use ECDH for initial key exchange, then symmetric AES-GCM
4. **Memory Isolation**: Never export WebAssembly.Memory from worker

## Message Flow

```
Host                           Enclave Worker
 |                                  |
 |---(1) Establish connection----->|
 |<--(2) Public key exchange--------|
 |                                  |
 |---(3) Encrypt(code, key)-------->|
 |                                  | - Decrypt(code)
 |                                  | - Execute in QuickJS
 |                                  | - Encrypt(result)
 |<--(4) Encrypt(result, key)-------|
 |                                  |
 | - Decrypt(result)                |
 |                                  |
```

## Threat Model

### In Scope
- Curious host trying to read enclave memory
- Network observer trying to read communication
- Same-origin attacks from other pages

### Out of Scope
- Hardware attacks (Spectre, Meltdown, etc.)
- Browser compromise
- User with DevTools access
- Physical access to device

## File Structure

```
soft-enclave/
├── src/
│   ├── host/
│   │   ├── index.html          # Host page
│   │   ├── main.js             # Host controller
│   │   └── crypto-client.js    # Encryption client
│   ├── enclave/
│   │   ├── worker.js           # Enclave worker
│   │   ├── crypto-worker.js    # Decryption worker-side
│   │   └── quickjs-loader.js   # Load QuickJS-Wasm
│   └── shared/
│       ├── crypto-protocol.js  # Shared crypto protocol
│       └── message-types.js    # Message type definitions
├── package.json
└── README.md
```

## Next Steps

1. Implement the crypto protocol with AES-GCM
2. Create the enclave worker that loads QuickJS
3. Implement the host-side communication layer
4. Build a proof-of-concept demo
5. Test memory isolation guarantees
