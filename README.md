# @fastnear/soft-enclave

Browser-based secure execution environment using QuickJS-WASM sandboxing with cross-origin isolation.

## What It Is

A defense-in-depth approach to browser security that provides measurable improvements over localStorage:
- **WebCrypto non-extractable keys** - Browser-enforced key protection
- **Cross-origin isolation** - Worker/iframe isolation barriers
- **QuickJS-WASM sandbox** - Memory-isolated execution
- **Ephemeral computation** - Keys exist plaintext only during ~30-50ms operations

**Not a hardware TEE** - This is a software-based approach providing practical security improvements for browser environments.

## Quick Start

```bash
# Install dependencies
yarn install

# Build all packages (required before first run)
yarn build

# Terminal 1 - Host app
yarn dev
# Opens at http://localhost:3000

# Terminal 2 - iframe backend (default, port 3010)
yarn dev:iframe
# Or for worker backend: yarn dev:worker (port 8081)
```

Visit http://localhost:3000 to see:
- Sandboxed code execution
- Ephemeral key operations with timing metrics
- NEAR transaction signing demo

## Basic Usage

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

const enclave = createEnclave();
await enclave.initialize();

// Execute sandboxed code
const { result, metrics } = await enclave.execute(`
  function fibonacci(n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
  }
  fibonacci(10);
`);

console.log('Result:', result); // 55
console.log('Key exposure window:', metrics.keyExposureMs, 'ms'); // ~40ms
```

## Architecture

### Dual Backend Support

| Backend | Isolation | Protocol | Use Case |
|---------|-----------|----------|----------|
| **iframe** (default) | Cross-origin iframe | Simple ECDH+HKDF | Production, CSP-compatible |
| **Worker** | Web Worker | Advanced (v1.1) with transcript binding | Performance-critical (requires blob: in CSP) |

```javascript
// iframe backend (default - works with strict CSP)
const enclave = createEnclave();

// Worker backend (requires blob: in worker-src CSP)
import { createEnclave, EnclaveMode } from '@fastnear/soft-enclave';
const enclave = createEnclave({
  mode: EnclaveMode.WORKER,
  workerUrl: 'http://localhost:8081/enclave-worker.js'
});
```

### Security Tiers

Choose based on transaction value:

| Tier | Value Range | Implementation |
|------|-------------|----------------|
| 1 | < $100 | In-page sandbox |
| 2 | $100-$10K | **Soft Enclave** (this project) |
| 3 | $10K-$100K | TEE backend |
| 4 | > $100K | Hardware wallet |

## Threat Model

### Defends Against
- XSS attacks targeting localStorage
- Basic browser extensions
- Malicious guest code (sandbox escape)
- Timing attacks (narrow window)

### Does NOT Defend Against
- Sophisticated attackers with persistent access
- Compromised browser/OS
- Hardware attacks (Spectre, etc)
- User with DevTools (by design)

## Key Features

### Non-Extractable Keys
```javascript
// Master key cannot be exported (browser enforced)
this.masterKey = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  false, // NOT extractable
  ['encrypt', 'decrypt']
);
```

### Ephemeral Operations
```javascript
// Keys exist in plaintext only during operation
const execution = await measureTiming(async () => {
  return await this.executeInQuickJS(code, context);
});
// Typical: 30-50ms exposure window
```

### NEAR Integration
```javascript
import { signTransaction } from '@fastnear/soft-enclave/near';

// Sign NEAR transaction with ephemeral key decryption
const signed = await enclave.signTransaction(transaction, privateKey);
```

## Development

```bash
# Run tests (unit + security)
yarn test:ci

# Test specific suites
yarn test:security      # Core security tests
yarn test:bundle        # IIFE bundle integration tests
yarn test:e2e          # End-to-end tests (requires RUN_E2E=1)
yarn test:hpke         # Experimental HPKE tests (requires RUN_HPKE=1)

# Build packages
yarn build

# Type checking
yarn type-check
```

## Demos

- `demo/test-runner.html` - Visual security tests
- `demo/examples/near-counter.html` - NEAR contract interaction
- `examples/persistence-demo.html` - Key custody demo

## Security Metrics

All operations provide measurable security metrics:
- Key exposure duration (target < 50ms)
- Memory zeroing confirmation
- Operation timing breakdowns

## When to Use

✅ **Good for:**
- Development and testing
- Low-to-moderate value operations ($100-$10K)
- User experience improvements over manual key entry
- Progressive security enhancement

❌ **Not for:**
- High-value operations (> $10K)
- Long-term key storage without user interaction
- Regulatory compliance requirements
- Protection against sophisticated targeted attacks

## References

- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Persistence & Key Custody](docs/PERSISTENCE.md)