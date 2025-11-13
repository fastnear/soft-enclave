# Soft Enclave Architecture

**Browser-based secure execution with multiple isolation backends and honest threat modeling**

## Executive Summary

This project implements a **pragmatic security improvement** over localStorage for browser-based private key custody and transaction signing. We achieve this through **defense-in-depth** combining:

1. **Cross-origin isolation** (Worker or iframe backends)
2. **Encrypted communication** (ECDH + HKDF + AES-GCM)
3. **QuickJS sandboxing** (Deterministic, capability-minimized execution)
4. **WebCrypto custody** (Non-extractable keys where possible)
5. **Ephemeral computation** (Keys exposed only during operations)

**We do not claim a "secure enclave" in the TEE sense.** We claim a **material reduction in attack surface** compared to storing private keys in localStorage or sessionStorage.

## Security Tier Model

This implementation focuses on **Tier 2** security (enhanced protection for moderate-value transactions).

| Tier | Value Range | Implementation | Security Features | Use Case |
|------|-------------|----------------|-------------------|----------|
| **Tier 1** | < $100 | In-page sandbox | WebCrypto custody, deterministic compute, strict CSP | Daily transactions, convenience-first |
| **Tier 2** | $100–$10K | **Soft Enclave (this project)** | Cross-origin isolation, encrypted RPC, defense-in-depth | Enhanced security for moderate-value ops |
| **Tier 3** | $10K–$100K | TEE backend | Hardware attestation, remote verification | High-value transactions |
| **Tier 4** | > $100K | Hardware wallet | Dedicated secure element | Treasury operations |

## Backend Architectures

This project supports **two isolation backends**, both implementing Tier 2 security with different trade-offs:

### Worker Backend (Default)

**Mechanism**: Web Worker with cross-origin isolation

**Advantages**:
- Cleaner security model (true thread isolation)
- Better for production deployment
- No DOM or cookies access
- Easier to reason about

**Architecture**:
```
┌─────────────────────────────────────────┐
│ Host Page (https://app.near.org)        │
│  ┌────────────────────────────────────┐ │
│  │ WorkerBackend                       │ │
│  │  - ECDH + context binding           │ │
│  │  - Advanced protocol (v1.1)         │ │
│  │  - Transcript binding               │ │
│  └────────────────────────────────────┘ │
└───────────┬─────────────────────────────┘
            │ postMessage (encrypted)
            ↓
┌─────────────────────────────────────────┐
│ Worker (https://enclave.near.org)       │
│  ┌────────────────────────────────────┐ │
│  │ Enclave Worker                      │ │
│  │  - QuickJS-WASM sandbox             │ │
│  │  - Replay protection (IV cache)     │ │
│  │  - Memory zeroing                   │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

**Security properties**:
- ✅ SOP barrier (cross-origin worker)
- ✅ No DOM/cookie access
- ✅ Advanced crypto protocol with transcript binding
- ✅ Strict sequence validation
- ✅ Message size limits (DoS protection)

### iframe Backend (Proven from near-outlayer)

**Mechanism**: Cross-origin iframe with MessageChannel

**Advantages**:
- Battle-tested in near-outlayer
- Explicit egress guard (runtime enforcement)
- Easier debugging (iframe inspector)
- CSP-hardened

**Architecture**:
```
┌─────────────────────────────────────────┐
│ Host Page (http://localhost:3000)       │
│  ┌────────────────────────────────────┐ │
│  │ IframeBackend                       │ │
│  │  - EnclaveClient                    │ │
│  │  - Simple ECDH+HKDF protocol        │ │
│  │  - Counter-based IVs                │ │
│  └────────────────────────────────────┘ │
└───────────┬─────────────────────────────┘
            │ MessageChannel (encrypted)
            ↓
┌─────────────────────────────────────────┐
│ iframe (http://localhost:3010)           │
│  ┌────────────────────────────────────┐ │
│  │ Egress Guard (LOADED FIRST)         │ │
│  │  - Blocks plaintext messages        │ │
│  │  - Schema validation                │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │ Enclave Main                        │ │
│  │  - QuickJS runtime                  │ │
│  │  - IV replay cache (4096 entries)   │ │
│  │  - Encrypted operations             │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

**Security properties**:
- ✅ SOP barrier (cross-origin iframe)
- ✅ Explicit egress guard (runtime patch)
- ✅ Tight CSP (script-src 'self', no inline)
- ✅ IV replay protection
- ✅ Context binding (origins + codeHash)

## Backend Comparison

| Feature | Worker Backend | iframe Backend |
|---------|----------------|----------------|
| **Isolation** | Web Worker | iframe + MessageChannel |
| **Protocol** | Advanced (v1.1) | Simple ECDH+HKDF |
| **Egress guard** | Implicit (no DOM) | Explicit (runtime patch) |
| **Debugging** | Harder | Easier (inspector) |
| **Production** | Recommended | Development/testing |
| **Maturity** | New | Battle-tested (near-outlayer) |
| **CSP** | Worker CSP | Strict HTML CSP |

## When to Use Each Backend

### Use Worker Backend When:
- Deploying to production
- Want cleanest security model
- Need advanced protocol features
- Don't need egress guard inspection

### Use iframe Backend When:
- Proving security properties
- Need egress guard visibility
- Easier debugging important
- Following near-outlayer patterns

## Cryptographic Protocols

### Simple Protocol (iframe backend)

```
Handshake:
1. Enclave generates ECDH keypair (P-256)
2. Host generates ECDH keypair (P-256)
3. Both derive session via:
   - ikm = ECDH.deriveBits(myPriv, peerPub)
   - salt = SHA-256(hostOrigin || enclaveOrigin || codeHash)
   - aeadKey = HKDF(ikm, salt, info="soft-enclave/aead") → AES-GCM-256
   - baseIV = HKDF(ikm, salt, info="soft-enclave/iv") → 96 bits

Encryption:
- IV(seq) = baseIV ⊕ (seq as 32-bit counter in last 4 bytes)
- ciphertext = AES-GCM.encrypt(aeadKey, IV(seq), plaintext, AAD)

Replay Protection:
- Enclave tracks seen IVs in Set (max 4096, FIFO eviction)
- Rejects duplicate IVs
```

### Advanced Protocol (worker backend)

Adds to simple protocol:
- **Transcript binding**: Self public key included in HKDF
- **Strict sequence validation**: Monotonically increasing sequences
- **Message size limits**: Max 1MB ciphertext, 256KB plaintext
- **AAD diversity**: Different AAD per operation type

## Security Properties Matrix

| Property | Worker Backend | iframe Backend |
|----------|----------------|----------------|
| **XSS resilience** | ✓✓✓ | ✓✓✓ |
| **Extension resistance** | ~ | ~ |
| **Memory confidentiality** | ✓ (SOP) | ✓ (SOP) |
| **Determinism** | ✓✓✓ | ✓✓✓ |
| **Protocol strength** | ✓✓✓ (advanced) | ✓✓ (simple) |
| **Egress visibility** | ✓ (implicit) | ✓✓✓ (explicit guard) |
| **Production ready** | ✓✓✓ | ✓✓ |

Legend: ✓✓✓ strong, ✓✓ moderate, ✓ limited, ~ marginal

## Usage Patterns

### Basic Usage (Worker Backend - Default)

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

// Create with default settings (worker + advanced protocol)
const enclave = createEnclave();
await enclave.initialize();

// Execute code
const { result } = await enclave.execute('40 + 2');
console.log(result); // 42

// Check metrics
const metrics = enclave.getMetrics();
console.log('Key exposure:', metrics.averageKeyExposureMs, 'ms');
```

### iframe Backend

```javascript
import { createEnclave, EnclaveMode } from '@fastnear/soft-enclave';

// Create iframe backend
const enclave = createEnclave({
  mode: EnclaveMode.IFRAME,
  enclaveOrigin: 'http://localhost:3010'
});

await enclave.initialize();
const { result } = await enclave.execute('fibonacci(10)');
```

### Security Tier Selection

```javascript
import { createEnclave, recommendTier } from '@fastnear/soft-enclave';

// Automatic tier selection based on transaction value
const transactionValue = 5000; // $5K USD
const tier = recommendTier(transactionValue);
// Returns: { mode: 'iframe', protocol: 'advanced', description: '...' }

const enclave = createEnclave(tier);
```

## Threat Model

### ✓ Defends Against

- **XSS attacks** trying to steal localStorage/sessionStorage
- **Unsophisticated browser extensions** with limited capabilities
- **Malicious guest code execution** (strong sandboxing)
- **Timing attacks** (narrow ~50ms exposure window)
- **Replay attacks** (IV deduplication)
- **MITM between host and enclave** (authenticated encryption)

### ✗ Does NOT Defend Against

- Sophisticated attackers with persistent browser access
- Compromised browser process
- User with DevTools access (by design - user's choice)
- Hardware attacks (Spectre, Meltdown)
- OS-level malware
- Malicious browser extensions with deep hooks

## Progressive Enhancement Path

```
┌─────────────────────┐
│   localStorage      │  ← Convenience only
│   (Tier 0)          │
└─────────────────────┘
          ↓
┌─────────────────────┐
│  Soft Enclave       │  ← This project (Tier 2)
│  Worker/iframe      │
│  - Cross-origin     │
│  - Encrypted RPC    │
└─────────────────────┘
          ↓
┌─────────────────────┐
│  TEE Backend        │  ← Future (Tier 3)
│  SGX/SEV/Nitro      │
│  + Attestation      │
└─────────────────────┘
          ↓
┌─────────────────────┐
│  Hardware Wallet    │  ← Treasury operations (Tier 4)
│  Ledger/Trezor      │
└─────────────────────┘
```

## Development & Testing

### Running Worker Backend

```bash
# Terminal 1: Host
npm run dev           # http://localhost:3000

# Terminal 2: Worker
npm run serve:enclave # http://localhost:3010
```

### Running iframe Backend

```bash
# Terminal 1: Host
npm run dev           # http://localhost:3000

# Terminal 2: iframe enclave
npm run serve:iframe  # http://localhost:3010
```

### Testing

```bash
# Unit tests (all backends)
npm test

# Browser tests (visual validation)
open http://localhost:3000/test-runner.html
```

## Production Deployment

### Worker Backend (Recommended)

```
Production URLs:
- Host:    https://app.near.org
- Worker:  https://enclave.near.org/enclave-worker.js

const enclave = createEnclave({
  mode: EnclaveMode.WORKER,
  workerUrl: 'https://enclave.near.org/enclave-worker.js'
});
```

### iframe Backend

```
Production URLs:
- Host:   https://app.near.org
- iframe: https://enclave.near.org

const enclave = createEnclave({
  mode: EnclaveMode.IFRAME,
  enclaveOrigin: 'https://enclave.near.org'
});
```

## Performance Characteristics

| Operation | Worker Backend | iframe Backend |
|-----------|----------------|----------------|
| **Initialize** | ~200-500ms | ~300-600ms |
| **Execute simple** | ~30-50ms | ~40-60ms |
| **Sign transaction** | ~40-60ms | ~50-70ms |
| **Key exposure** | ~30-50ms | ~40-60ms |

Key exposure time is the critical security metric - the duration that decrypted secrets exist in memory.

## References

- [near-outlayer soft-enclave](https://github.com/near/near-outlayer) - Original iframe implementation
- [QuickJS](https://bellard.org/quickjs/) - JavaScript engine
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
