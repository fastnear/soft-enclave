# Soft Enclave

Browser-based soft enclave using QuickJS-WASM with cross-origin isolation and encrypted communication.

## Overview

This project implements a **practical security improvement** over localStorage for sensitive operations in the browser. It uses a defense-in-depth approach combining:

1. **WebCrypto non-extractable keys** (primary defense)
2. **Cross-origin isolation** (Worker or iframe backends)
3. **QuickJS-WASM sandboxing** (execution isolation)
4. **Ephemeral computation** (limited exposure window)

## Security Tier Model

This implementation provides **Tier 2** security (enhanced protection for moderate-value transactions). Choose the appropriate tier based on transaction value:

| Tier | Value Range | Implementation | Best For |
|------|-------------|----------------|----------|
| **Tier 1** | < $100 | In-page sandbox | Daily transactions, convenience |
| **Tier 2** | $100–$10K | **Soft Enclave (this project)** | Enhanced security, moderate value |
| **Tier 3** | $10K–$100K | TEE backend | High-value transactions |
| **Tier 4** | > $100K | Hardware wallet | Treasury operations |

### Backend Architectures

Soft Enclave supports **two isolation backends** with different trade-offs:

| Feature | Worker Backend (Default) | iframe Backend |
|---------|--------------------------|----------------|
| **Isolation** | Web Worker | iframe + MessageChannel |
| **Protocol** | Advanced (v1.1) | Simple ECDH+HKDF |
| **Production** | ✅ Recommended | Development/testing |
| **Debugging** | Harder | Easier (inspector) |
| **Maturity** | New | Battle-tested (near-outlayer) |

**Worker Backend** (default): Cleanest security model, true thread isolation, recommended for production

**iframe Backend**: Explicit egress guard, easier debugging, proven in near-outlayer

## Honest Threat Model

### ✓ Defends Against

- **XSS attacks** trying to steal localStorage/sessionStorage
- **Unsophisticated browser extensions** with limited capabilities
- **Malicious guest code execution** (strong sandboxing)
- **Timing attacks** (narrow ~50ms window)

### ✗ Does NOT Defend Against

- Sophisticated attackers with persistent browser access
- Compromised browser process
- User with DevTools access (by design - user's choice)
- Hardware attacks (Spectre, Meltdown)
- OS-level malware

## Use Case Guidance

- ✓ **Good for**: Daily transactions, low-to-medium value operations, development
- ✗ **Not for**: Large treasury management, high-value custody
- → **For high-stakes**: Use hardware wallet or TEE-backed solution

---

## Quick Start

### Prerequisites

- Node.js 18+
- Modern browser (Chrome, Firefox, Safari, Edge)

### Installation

```bash
npm install
```

### Running the Demo

You need **two terminal windows** for cross-origin isolation.

#### Option A: Worker Backend (Default - Recommended)

**Terminal 1 - Host application:**
```bash
npm run dev
# Opens at http://localhost:3000
```

**Terminal 2 - Enclave worker:**
```bash
npm run serve:enclave
# Serves worker at http://localhost:8081
```

#### Option B: iframe Backend (Easier Debugging)

**Terminal 1 - Host application:**
```bash
npm run dev
# Opens at http://localhost:3000
```

**Terminal 2 - iframe enclave:**
```bash
npm run serve:iframe
# Serves iframe at http://localhost:8091
```

Then open **http://localhost:3000** and try:
- Execute Code (Fibonacci example)
- Try Malicious Code (see sandbox in action)
- Sign Transaction (ephemeral key decryption)
- Switch backends (compare worker vs iframe)

### Testing

```bash
npm test
```

---

## Usage

### Basic API

#### Worker Backend (Default)

```javascript
import { createEnclave } from '@near/soft-enclave';

// 1. Create with default settings (worker + advanced protocol)
const enclave = createEnclave();
await enclave.initialize();

// 2. Execute code safely
const { result, metrics } = await enclave.execute(`
  function fibonacci(n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
  }
  fibonacci(10);
`);

console.log('Result:', result); // 55
console.log('Key exposed for:', metrics.keyExposureMs, 'ms'); // ~40ms
```

#### iframe Backend

```javascript
import { createEnclave, EnclaveMode } from '@near/soft-enclave';

// Create iframe backend
const enclave = createEnclave({
  mode: EnclaveMode.IFRAME,
  enclaveOrigin: 'http://localhost:8091'
});

await enclave.initialize();
const { result } = await enclave.execute('40 + 2');
console.log(result); // 42
```

#### Automatic Tier Selection

```javascript
import { createEnclave, recommendTier } from '@near/soft-enclave';

// Choose backend based on transaction value
const transactionValue = 5000; // $5K USD
const tier = recommendTier(transactionValue);
// Returns: { mode: 'iframe', protocol: 'advanced', ... }

const enclave = createEnclave(tier);
await enclave.initialize();
```

### Sign Transactions

```javascript
// NEAR transaction signing with ephemeral key decryption
const transaction = {
  signerId: 'alice.near',
  receiverId: 'bob.near',
  actions: [{
    type: 'Transfer',
    amount: '1000000000000000000000000' // 1 NEAR
  }]
};

const { signature, metrics } = await enclave.signTransaction(
  encryptedPrivateKey,
  transaction
);

// Private key existed in plaintext for only ~30-50ms
console.log('Key exposure:', metrics.keyExposureMs, 'ms');
```

### Custom Worker URL

```javascript
// For production, specify your enclave domain
const enclave = new HybridSecureEnclave(
  'https://enclave.your-domain.com/worker.js'
);
```

### Monitor Security Metrics

```javascript
const metrics = enclave.getMetrics();

console.log('Total operations:', metrics.totalOperations);
console.log('Average key exposure:', metrics.averageKeyExposureMs, 'ms');
console.log('Max key exposure:', metrics.maxKeyExposureMs, 'ms');

// Alert if performance degrades
if (metrics.averageKeyExposureMs > 100) {
  console.warn('Performance degraded, consider refreshing enclave');
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Host Page (https://wallet.near.org)                    │
│                                                         │
│  ┌──────────────────────────────────────┐             │
│  │ WebCrypto (Non-extractable Key)      │             │
│  │  - Encrypts before sending            │             │
│  │  - Decrypts after receiving           │             │
│  └──────────────────────────────────────┘             │
│                     │                                   │
│                     │ postMessage (encrypted)           │
│                     ▼                                   │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Enclave Worker (https://enclave.near.org)              │
│                                                         │
│  ┌──────────────────────────────────────┐             │
│  │ QuickJS-WASM                          │             │
│  │  - Decrypts payload                   │             │
│  │  - Executes operation (~50ms)         │             │
│  │  - Zeros memory                       │             │
│  │  - Encrypts result                    │             │
│  └──────────────────────────────────────┘             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Defense-in-Depth Layers

To extract sensitive data, an attacker must:

1. **Compromise non-extractable WebCrypto key** (browser internal)
2. **Bypass same-origin policy** (access cross-origin Memory handle)
3. **Time attack precisely** (during ~50ms window)
4. **Locate data in WASM heap** (no fixed addresses)
5. **Bypass memory zeroing** (explicit cleanup)

Each layer independently raises the bar.

---

## Security Comparison

| Method | XSS Protection | Extension Protection | Persistent Access | Hardware Backed |
|--------|---------------|---------------------|-------------------|-----------------|
| localStorage | ✗ | ✗ | ✗ | ✗ |
| sessionStorage | ✗ | ✗ | Partial | ✗ |
| **This implementation** | **✓ (Moderate)** | **✓ (Limited)** | **✓ (Ephemeral)** | **✗** |
| Hardware Wallet | ✓ | ✓ | ✓ | ✓ |

## Progressive Enhancement

```javascript
enum SecurityLevel {
  BASIC = 'localStorage',      // Convenience only
  IMPROVED = 'soft-enclave',   // This implementation
  STRONG = 'hardware-tee',     // Ledger/SGX/etc
}

// Adapt security based on transaction value
if (txValue > HIGH_THRESHOLD) {
  throw new Error('High-value transaction requires hardware wallet');
}
```

---

## Development

### Project Structure

```
soft-enclave/
├── README.md              # This file
├── CLAUDE.md              # Developer documentation
├── package.json
├── vite.config.js
├── src/
│   ├── host/              # Host-side code
│   │   └── hybrid-enclave.js
│   ├── enclave/           # Worker code
│   │   └── enclave-worker.js
│   └── shared/            # Shared utilities
│       ├── crypto-protocol.js
│       └── message-types.js
├── test/                  # Test suite (9 files)
├── demo/                  # Demo application
└── thoughts/              # Research & design docs
```

### Running Tests

```bash
# All tests
npm test

# Specific test suites
npm test test/crypto-protocol.test.js
npm test test/isolation.test.js
```

### Build for Production

```bash
npm run build
npm run preview
```

---

## Performance Tips

### 1. Reuse Enclave Instance

```javascript
// GOOD: Initialize once, use many times
const enclave = new HybridSecureEnclave();
await enclave.initialize();

for (let i = 0; i < 100; i++) {
  await enclave.execute(code);
}
```

### 2. Batch Operations

```javascript
// Execute multiple operations in one call
await enclave.execute(`
  const results = [];
  for (const item of items) {
    results.push(processItem(item));
  }
  return results;
`, { items: yourData });
```

### 3. Monitor Metrics

Keep key exposure < 100ms for optimal security.

---

## Common Issues

### "Worker failed to load"

**Problem:** Enclave server not running

**Solution:**
```bash
npm run serve:enclave  # Terminal 2
```

### CORS errors

**Problem:** Browser blocking cross-origin requests

**Solution:** Ensure both servers are running (dev + serve:enclave)

### Tests skip with "not initialized"

**Expected:** Some isolation tests require a live worker and skip by default.

---

## Security Checklist

Before production:

- [ ] Understand the threat model
- [ ] Verify key exposure metrics (<100ms)
- [ ] Implement progressive enhancement for high-value operations
- [ ] Add transaction value thresholds
- [ ] Set up monitoring for security metrics
- [ ] Use hardware wallet for high-stakes operations

---

## References

- [WebAssembly Security Overview](https://webassembly.org/docs/security/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [QuickJS-Emscripten](https://github.com/justjake/quickjs-emscripten)
- [Cross-Origin Isolation](https://web.dev/articles/coop-coep)

## Documentation

- **CLAUDE.md** - Developer guide and contribution guidelines
- **thoughts/** - Research, design decisions, and threat model analysis

## License

MIT
