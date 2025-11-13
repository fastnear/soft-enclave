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

# Choose one of these options:

# Option 1: Run both servers together (RECOMMENDED)
yarn dev:iframe  # Runs both host (3000) and enclave (3010)

# Option 2: Run servers separately
# Terminal 1 - Host app
yarn dev  # Opens at http://localhost:3000

# Terminal 2 - Enclave server (choose one):
# For iframe backend (default, CSP-compatible):
ENCLAVE_PORT=3010 HOST_ORIGIN=http://localhost:3000 node enclave-server.js

# For worker backend (requires blob: in CSP):
yarn dev:worker  # Also runs on port 3010
```

Visit http://localhost:3000 to see:
- Sandboxed code execution
- Ephemeral key operations with timing metrics
- NEAR transaction signing demo

**Port Usage:**
- `3000` - Main application (Vite dev server)
- `3010` - Enclave server (used by both iframe and worker backends)

## Basic Usage

### Getting Started

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

// Create and initialize the enclave
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

### Understanding Execution Context

Each execution is **completely isolated**:

```javascript
// First execution - define a variable
await enclave.execute(`
  const mySecret = 'hidden value';
  return 'Variable set!';
`);

// Second execution - variable doesn't exist!
const { result } = await enclave.execute(`
  return typeof mySecret; // 'undefined' - no persistence!
`);
```

### Working with NEAR

For NEAR operations, use the built-in shims:

```javascript
const { result } = await enclave.execute(`
  // Store data (simulated blockchain storage)
  near.storageWrite('user:alice', JSON.stringify({ balance: 100 }));

  // Read it back
  const data = near.storageRead('user:alice');
  return JSON.parse(data);
`);
// Returns: { balance: 100 }
```

### Passing Context

Need to share data between executions? Pass it explicitly:

```javascript
const context = {
  privateKey: 'ed25519:...',  // Will be available during execution
  data: { message: 'Hello!' }
};

const { result } = await enclave.execute(`
  // Context variables are available here
  const signed = signMessage(context.data.message, context.privateKey);
  return signed;
`, context);
```

## Architecture

### Dual Backend Support (Choose One!)

The enclave supports two different isolation backends. **You pick one based on your needs**:

| Backend | How It Isolates | Best For | Key Requirement |
|---------|----------------|----------|-----------------|
| **iframe** (default) | Cross-origin iframe on port 3010 | Most users, production | Standard CSP |
| **Worker** | Web Worker via Blob URL | Performance-critical apps | CSP must allow `blob:` |

**Same API, same security, different isolation techniques!**

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

### 🧪 Visual Security Test Runner
**Location**: `http://localhost:3000/demo/test-runner.html`

Live security property verification in your browser. Watch the isolation actually work!

**What You'll See**:
- ✅ **Basic Execution** - Confirms sandboxed code runs correctly
- ✅ **SOP Barrier** - Guest code can't access `window`, `document`, or `fetch`
- ✅ **Replay Protection** - Captured/replayed messages are rejected
- ✅ **Context Binding** - Messages bound to specific contexts

**Why It Matters**: You can SEE the security properties in action, not just read about them

---

### 🔐 Persistence Demo
**Location**: `http://localhost:3000/examples/persistence-demo.html`

Interactive demonstration of key custody and encrypted storage.

**Key Features**:
1. **🔑 Keystore Section**
   - Store NEAR private keys (ed25519)
   - Generate test keys
   - Sign data with stored keys
   - Shows key exposure timing (~30-50ms)

2. **💾 Encrypted Storage**
   - Store arbitrary JSON data
   - Encrypted with AES-GCM
   - Query and retrieve data
   - Type categorization support

3. **📊 Security Metrics**
   - Average key exposure time
   - Total operations count
   - Real-time performance tracking

**Important**: Each code execution is isolated - no persistent JavaScript state! The persistence is for keys/data in IndexedDB, not runtime state.

---

### 🔢 NEAR Counter Demo
**Location**: `http://localhost:3000/demo/examples/near-counter.html`

Simulates a NEAR smart contract with persistent storage.

**How It Works**:
```javascript
// Contract maintains a counter in storage
near.storageWrite('counter', (current + 1).toString());

// Next execution can read the state
const counter = parseInt(near.storageRead('counter') || '0');
```

**Try It**:
- Increment/decrement the counter
- Reset to zero
- Watch gas usage simulation
- See how contract state persists between executions

---

### ⚖️ Mode Comparison Demo
**Location**: `http://localhost:3000/demo/examples/mode-comparison.html`

Side-by-side comparison of Worker vs iframe backends.

| Feature | iframe Backend | Worker Backend |
|---------|----------------|----------------|
| **CSP Requirements** | Standard ✅ | Needs `blob:` ⚠️ |
| **Debugging** | Easy (DevTools) | Limited |
| **Performance** | ~45ms overhead | ~40ms overhead |
| **Best For** | Production | Performance-critical |

Both use the same API - choose based on your CSP constraints!

---

### 🎮 Main Interactive Playground
**Location**: `http://localhost:3000/`

The main demo - try everything in one place!

**Built-in Examples**:
1. **Fibonacci** - Basic computation
2. **Crypto Operations** - Ephemeral key usage
3. **NEAR Transaction** - Sign a real transaction
4. **Attack Attempts** - Try to break out (spoiler: you can't!)

**Live Metrics**:
- ⏱️ **Key Exposure** - How long keys exist in plaintext
- 📏 **Total Duration** - Full operation time
- 🧹 **Memory Zeroing** - Cleanup confirmation

**Pro Tip**: Open DevTools and try to access the enclave's memory - you'll see why we use cross-origin isolation!

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

## Common Questions

### "Why doesn't my code persist between executions?"

Each execution gets a fresh QuickJS context for security. This is intentional!

```javascript
// ❌ This won't work:
await enclave.execute(`const myVar = 42;`);
await enclave.execute(`return myVar;`); // Error: myVar is not defined

// ✅ Do this instead:
// Option 1: Use storage for persistence
await enclave.execute(`
  near.storageWrite('myVar', '42');
`);
await enclave.execute(`
  const myVar = near.storageRead('myVar');
  return parseInt(myVar); // 42
`);

// Option 2: Pass data via context
const context = { myVar: 42 };
await enclave.execute(`return context.myVar;`, context); // 42
```

### "What's the difference between the demos?"

- **Main Demo** (`/`) - Interactive playground, try anything
- **Test Runner** (`/demo/test-runner.html`) - Proves security properties work
- **Persistence Demo** (`/examples/persistence-demo.html`) - Key/data storage (not JS state!)
- **NEAR Counter** (`/demo/examples/near-counter.html`) - Simulated smart contract
- **Mode Comparison** (`/demo/examples/mode-comparison.html`) - iframe vs Worker

### "How secure is this really?"

We're honest about it:
- ✅ **Great for**: Development, testing, low-value operations
- ✅ **Protects against**: XSS, basic attacks, malicious guest code
- ❌ **Doesn't protect against**: Sophisticated attackers, compromised browser/OS
- ❌ **Not equivalent to**: Hardware security modules or TEEs

See our [Threat Model](docs/THREAT_MODEL.md) for complete details.

### "Why two different backends?"

Think of them as two different isolation techniques - you pick ONE:

#### 🖼️ iframe Backend (Default)
Creates a cross-origin iframe on a different port:
```
Your App (localhost:3000)
    ↓ postMessage
iframe (localhost:3010) ← Different origin = isolation!
    ↓
QuickJS-WASM sandbox
```

**Choose this if**:
- You're getting started (it's the default)
- You have strict CSP that blocks `blob:` URLs
- You want better debugging (DevTools iframe inspection)
- You're going to production

**Trade-offs**: Requires two servers, ~5ms slower

#### 🔧 Worker Backend
Creates a Web Worker from a Blob URL:
```
Your App
    ↓ new Worker(blob://...)
Web Worker ← Separate thread = isolation!
    ↓
QuickJS-WASM sandbox
```

**Choose this if**:
- Every millisecond counts
- Your CSP allows `worker-src blob:`
- You prefer thread-based isolation

**Trade-offs**: Harder to debug, requires CSP relaxation

#### Quick Comparison
| | iframe | Worker |
|---|---|---|
| **Setup** | 2 servers | 1 server |
| **CSP** | Standard ✅ | Needs blob: ⚠️ |
| **Speed** | ~45ms | ~40ms |
| **Debugging** | Easy | Limited |
| **Recommendation** | **Use this** | Special cases |

Both provide the same security properties!

## References

- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Persistence & Key Custody](docs/PERSISTENCE.md)