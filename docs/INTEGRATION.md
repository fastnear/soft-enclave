# Integration Guide

**Complete guide to integrating soft-enclave into your application**

**Goal**: Get from zero to production-ready integration in < 30 minutes

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [CSP Configuration](#csp-configuration-critical)
5. [Backend Selection](#backend-selection-guide)
6. [Common Integration Patterns](#common-integration-patterns)
7. [Production Deployment](#production-deployment-checklist)
8. [Security Best Practices](#security-best-practices)
9. [Troubleshooting](#troubleshooting)
10. [Migration from localStorage](#migration-from-localstorage)
11. [API Reference](#api-reference-summary)
12. [Examples](#examples)

---

## Prerequisites

### Required

- **Node.js 18+** (for build tools)
- **Modern browser** with:
  - WebCrypto API support
  - SharedArrayBuffer support
  - COOP/COEP header support
- **Build tool**: Vite, webpack, or similar (ES modules support)

### Browser Compatibility

| Browser | Minimum Version | Notes |
|---------|-----------------|-------|
| Chrome | 92+ | Full support |
| Firefox | 95+ | Full support |
| Safari | 15.2+ | WebCrypto + COOP/COEP |
| Edge | 92+ | Full support |

**Check support**: Run this in browser console:

```javascript
// Check WebCrypto
console.log('WebCrypto:', !!window.crypto?.subtle);

// Check SharedArrayBuffer
console.log('SharedArrayBuffer:', typeof SharedArrayBuffer !== 'undefined');

// Check if headers allow cross-origin isolation
console.log('Cross-origin isolated:', crossOriginIsolated);
```

---

## Installation

### 1. Install via npm/yarn

```bash
# Using npm
npm install @fastnear/soft-enclave

# Using yarn
yarn add @fastnear/soft-enclave
```

### 2. Install dependencies

The package has peer dependencies on QuickJS and crypto libraries:

```bash
npm install quickjs-emscripten@0.31.0 tweetnacl@1.0.3
```

### 3. Verify installation

```javascript
import { createEnclave } from '@fastnear/soft-enclave';
console.log('Soft enclave installed:', typeof createEnclave === 'function');
```

---

## Quick Start

### Minimal Working Example (< 10 lines)

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

// 1. Create enclave instance (defaults to iframe backend)
const enclave = createEnclave();

// 2. Initialize (establishes secure channel)
await enclave.initialize();

// 3. Execute sandboxed code
const { result, metrics } = await enclave.execute(`
  function fibonacci(n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
  }
  fibonacci(10);
`);

console.log('Result:', result); // 55
console.log('Key exposure:', metrics.keyExposureMs, 'ms'); // ~45ms
```

**Expected output:**
```
Result: 55
Key exposure: 42 ms
```

### With Error Handling

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

try {
  const enclave = createEnclave();
  await enclave.initialize();

  const { result, metrics } = await enclave.execute('40 + 2');
  console.log('✓ Enclave working:', result === 42);

} catch (error) {
  console.error('✗ Enclave initialization failed:', error.message);
  // Common causes: CSP blocking, COOP/COEP headers missing, port 3010 unavailable
}
```

---

## CSP Configuration (CRITICAL)

Content Security Policy configuration is **required** for cross-origin isolation. Incorrect CSP is the #1 cause of initialization failures.

### iframe Backend (Default - Recommended)

**Host Application CSP** (port 3000):

```javascript
// In your server or meta tag
{
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'", // Required for WASM
    "frame-src 'self' http://localhost:3010", // Allow enclave iframe
    "child-src 'self' http://localhost:3010", // Legacy fallback
    "connect-src 'self' http://localhost:3010" // API calls
  ].join('; ')
}
```

**Enclave Server CSP** (port 3010):

```javascript
// Enclave server (enclave-server.js or your hosting)
{
  "Content-Security-Policy": [
    "default-src 'none'", // Deny by default
    "script-src 'self' 'wasm-unsafe-eval'",
    "connect-src 'self' data:", // data: required for QuickJS WASM
    "frame-ancestors http://localhost:3000" // Only allow your host
  ].join('; '),
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "cross-origin"
}
```

### Worker Backend

**Host Application CSP**:

```javascript
{
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self' blob:", // blob: required for Worker creation
    "connect-src 'self' http://localhost:3010"
  ].join('; ')
}
```

### Production CSP Example

```javascript
// Production with HTTPS
{
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "frame-src 'self' https://enclave.yourdomain.com",
    "connect-src 'self' https://enclave.yourdomain.com https://rpc.testnet.near.org",
    "style-src 'self' 'unsafe-inline'", // If needed
    "img-src 'self' data: https:" // If needed
  ].join('; ')
}
```

### Verify CSP with curl

```bash
# Check host CSP
curl -sI http://localhost:3000 | grep -i "content-security-policy"

# Check enclave headers
curl -sI http://localhost:3010 | grep -E -i "cross-origin|content-security-policy"

# Expected enclave headers:
# Cross-Origin-Opener-Policy: same-origin
# Cross-Origin-Embedder-Policy: require-corp
# Content-Security-Policy: default-src 'none'; ...
```

---

## Backend Selection Guide

### Decision Matrix

| Criterion | iframe Backend | Worker Backend |
|-----------|----------------|----------------|
| **CSP Requirements** | Standard ✅ | Needs `blob:` ⚠️ |
| **Setup Complexity** | 2 servers | 1 server + blob: CSP |
| **Debugging** | Easy (iframe inspector) | Limited |
| **Performance** | ~45ms | ~40ms |
| **Production Ready** | ✅ Yes | ✅ Yes |
| **Security** | Explicit egress guard | Implicit (no DOM) |
| **Recommendation** | **Use for most cases** | Performance-critical only |

### When to Use iframe Backend

✅ **Use if**:
- Getting started (it's the default)
- You have strict CSP that blocks `blob:`
- You want easier debugging (DevTools iframe inspection)
- You're going to production (battle-tested)
- You need explicit egress guard visibility

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

const enclave = createEnclave(); // iframe is default
await enclave.initialize();
```

### When to Use Worker Backend

✅ **Use if**:
- Every millisecond counts (~5ms faster)
- Your CSP allows `worker-src blob:`
- You prefer thread-based isolation

```javascript
import { createEnclave, EnclaveMode } from '@fastnear/soft-enclave';

const enclave = createEnclave({
  mode: EnclaveMode.WORKER,
  workerUrl: 'http://localhost:3010/enclave-worker.js'
});
await enclave.initialize();
```

---

## Common Integration Patterns

### Pattern 1: Basic Sandboxed Execution

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

const enclave = createEnclave();
await enclave.initialize();

// Execute untrusted user code safely
const userCode = getUserSubmittedCode(); // From form, API, etc.

const { result, metrics } = await enclave.execute(userCode);

console.log('User code result:', result);
console.log('Execution took:', metrics.totalDurationMs, 'ms');
```

**Security notes**:
- User code has no access to `window`, `document`, `fetch`
- Execution is time-limited (default 2000ms timeout)
- Each execution is isolated (no persistent state)

### Pattern 2: NEAR Transaction Signing

```javascript
import { createEnclave } from '@fastnear/soft-enclave';

const enclave = createEnclave();
await enclave.initialize();

// Sign a NEAR transaction
const transaction = {
  receiverId: 'example.testnet',
  actions: [{
    type: 'FunctionCall',
    params: {
      methodName: 'set_greeting',
      args: { greeting: 'Hello!' },
      gas: '30000000000000',
      deposit: '0'
    }
  }]
};

const { result, metrics } = await enclave.signTransaction(
  transaction,
  encryptedPrivateKey, // From keystore
  rpcUrl: 'https://rpc.testnet.near.org'
);

console.log('Signed tx:', result.signedTransaction);
console.log('Key was exposed for:', metrics.keyExposureMs, 'ms');
```

**Security notes**:
- Private key only exists in plaintext for ~40-50ms
- Egress guard ensures RPC calls only go to allowed hosts
- Memory is zeroed after signing

### Pattern 3: Key Custody with Encrypted Storage

```javascript
import { createEnclave } from '@fastnear/soft-enclave';
import { KeyStore } from '@fastnear/soft-enclave/keystore';

const enclave = createEnclave();
await enclave.initialize();

const keystore = new KeyStore();

// Store a new key
await keystore.storeKey(
  'alice.testnet',
  privateKeyString,
  { accountType: 'user' }
);

// Later: Sign with stored key
const signature = await keystore.signData(
  'alice.testnet',
  messageToSign
);

console.log('Signature:', signature);
console.log('Average key exposure:', keystore.getMetrics().averageKeyExposureMs);
```

**Security notes**:
- Keys are wrapped with WebCrypto non-extractable master key
- Master key never leaves WebCrypto
- Each sign operation tracked with timing metrics

### Pattern 4: Multi-Account Management

```javascript
import { KeyStore } from '@fastnear/soft-enclave/keystore';

const keystore = new KeyStore();

// Store multiple accounts
await keystore.storeKey('alice.testnet', aliceKey);
await keystore.storeKey('bob.testnet', bobKey);
await keystore.storeKey('treasury.testnet', treasuryKey);

// List all accounts
const accounts = await keystore.listKeys();
console.log('Managed accounts:', accounts); // ['alice.testnet', 'bob.testnet', ...]

// Sign with specific account
const sig = await keystore.signData('alice.testnet', message);
```

### Pattern 5: Passing Context to Enclave

```javascript
const context = {
  apiKey: 'secret-key',
  userData: { userId: 123, role: 'admin' }
};

const { result } = await enclave.execute(`
  // Context variables are available
  const user = context.userData;
  const response = callAPI(context.apiKey, user.userId);
  return response;
`, context);
```

**Security notes**:
- Context is passed encrypted over MessageChannel
- Each execution gets fresh context (no persistent state)
- Don't put keys directly in context (use keystore instead)

### Pattern 6: Transaction Value-Based Tier Selection

```javascript
import { createEnclave, recommendTier } from '@fastnear/soft-enclave';

async function signTransaction(tx, value) {
  // Select security tier based on transaction value
  const tier = recommendTier(value);

  if (tier.requiresHardwareWallet) {
    // Redirect to hardware wallet flow
    return await connectLedger();
  }

  // Use soft enclave for moderate values
  const enclave = createEnclave(tier);
  await enclave.initialize();
  return await enclave.signTransaction(tx);
}

// Usage
await signTransaction(tx, 500); // Uses soft enclave
await signTransaction(tx, 50000); // Prompts for hardware wallet
```

---

## Production Deployment Checklist

### Pre-Deployment

- [ ] **HTTPS enforced** on all domains
- [ ] **COOP/COEP headers** configured correctly
- [ ] **CSP tested** with curl/browser inspector
- [ ] **Enclave origin** on separate subdomain (e.g., `enclave.yourdomain.com`)
- [ ] **RPC endpoints** allowlisted in egress guard
- [ ] **Error handling** implemented for all enclave operations
- [ ] **Fallback flow** for unsupported browsers

### Security Configuration

- [ ] **Key exposure metrics** monitored (alert if > 100ms)
- [ ] **Transaction value thresholds** set (soft enclave vs hardware wallet)
- [ ] **User warnings** about DevTools/extensions displayed
- [ ] **Rate limiting** on enclave operations
- [ ] **Audit logging** for all signing operations

### Performance

- [ ] **Enclave initialization** preloaded (not on-demand)
- [ ] **WASM files** served with correct MIME type (`application/wasm`)
- [ ] **CDN** configured for static assets
- [ ] **Monitoring** for enclave initialization failures

### Testing

- [ ] **Cross-browser testing** (Chrome, Firefox, Safari, Edge)
- [ ] **CSP violations** checked (no console errors)
- [ ] **Network failures** handled gracefully
- [ ] **Concurrent operations** tested (multiple users)

### Production URLs

```javascript
// Development
const ENCLAVE_ORIGIN = 'http://localhost:3010';

// Production
const ENCLAVE_ORIGIN = process.env.NODE_ENV === 'production'
  ? 'https://enclave.yourdomain.com'
  : 'http://localhost:3010';

const enclave = createEnclave({
  enclaveOrigin: ENCLAVE_ORIGIN
});
```

---

## Security Best Practices

### ✅ DO

| Practice | Why | Example |
|----------|-----|---------|
| **Use keystore for private keys** | Proper wrapping + metrics | `keystore.storeKey(...)` |
| **Monitor key exposure times** | Detect anomalies | `if (metrics.keyExposureMs > 100) alert()` |
| **Implement value thresholds** | Upgrade to hardware wallet | `if (value > $10K) useHardwareWallet()` |
| **Preload enclave** | Faster UX | `enclave.initialize()` on app load |
| **Log all signing operations** | Audit trail | `auditLog.record({ account, tx, timestamp })` |
| **Warn about DevTools** | User awareness | "Opening DevTools exposes keys" |
| **Test CSP in staging** | Catch issues early | `curl -I staging.yourdomain.com` |
| **Use HTTPS in production** | Prevent MITM | Always |

### ❌ DON'T

| Anti-Pattern | Why | Instead |
|--------------|-----|---------|
| **Store keys in localStorage** | No protection | Use keystore |
| **Skip error handling** | Silent failures | `try/catch` all operations |
| **Ignore key exposure metrics** | Can't detect attacks | Monitor and alert |
| **Use for high-value ops** | Not sufficient security | Use hardware wallet > $10K |
| **Log plaintext keys** | Security leak | Never log sensitive data |
| **Skip browser compatibility checks** | Users get errors | Check WebCrypto/COOP support |
| **Use same origin** | Defeats isolation | Use separate subdomain |
| **Disable CSP in production** | Removes protection | Fix CSP, don't disable |

---

## Troubleshooting

### Error: "Refused to frame ... violates CSP"

**Cause**: Missing `frame-src` in host CSP

**Fix**:

```javascript
// Add to host CSP:
"frame-src 'self' http://localhost:3010"
"child-src 'self' http://localhost:3010" // Legacy fallback
```

**Verify**:

```bash
curl -sI http://localhost:3000 | grep -i "content-security-policy"
# Should include: frame-src ... http://localhost:3010
```

### Error: "Failed to fetch WASM ... violates CSP"

**Cause**: Missing `data:` in enclave CSP `connect-src`

**Fix**:

```javascript
// In enclave-server.js:
"connect-src 'self' data:" // data: required for QuickJS WASM
```

**Verify**:

```bash
curl -sI http://localhost:3010 | grep -i "content-security-policy"
# Should include: connect-src 'self' data:
```

### Error: "WebAssembly.instantiate aborted"

**Causes**:
1. Wrong Content-Type on .wasm files
2. Missing CORS headers
3. COEP blocking cross-origin WASM

**Fix**:

```javascript
// Ensure enclave server sends:
{
  'Content-Type': 'application/wasm',
  'Cross-Origin-Resource-Policy': 'cross-origin',
  'Access-Control-Allow-Origin': 'http://localhost:3000'
}
```

**Verify**:

```bash
curl -sI http://localhost:3010/vendor/quickjs-emscripten.wasm
# Should show: Content-Type: application/wasm
```

### Error: "Enclave initialization timeout"

**Causes**:
1. Enclave server not running (port 3010)
2. Network blocking requests
3. COOP/COEP headers blocking iframe

**Fix**:

```bash
# 1. Check enclave server is running
lsof -i:3010
# Should show: node (PID) ... LISTEN

# 2. Check enclave server responds
curl http://localhost:3010/boot.html
# Should return HTML

# 3. Check COOP/COEP headers
curl -sI http://localhost:3010 | grep -i "cross-origin"
# Should show COOP and COEP headers
```

### High Key Exposure Times (> 100ms)

**Causes**:
1. Slow machine/browser
2. Many concurrent operations
3. Large transaction payloads

**Fix**:

```javascript
// 1. Monitor and alert
if (metrics.keyExposureMs > 100) {
  console.warn('High key exposure:', metrics.keyExposureMs);
  // Consider: Reduce concurrency, optimize code, upgrade hardware
}

// 2. Implement timeout
const { result } = await Promise.race([
  enclave.signTransaction(tx),
  timeout(5000, 'Signing timeout')
]);
```

### Browser Shows "Not Secure" Warning

**Cause**: Using HTTP in production

**Fix**: Enforce HTTPS

```javascript
// In server
if (process.env.NODE_ENV === 'production' && req.protocol !== 'https') {
  return res.redirect(301, `https://${req.hostname}${req.url}`);
}
```

---

## Migration from localStorage

### Before (localStorage - Vulnerable)

```javascript
// ❌ Vulnerable to XSS
const privateKey = localStorage.getItem('privateKey');
const signedTx = signTransaction(privateKey, tx);
```

**Attack surface**: Any XSS can steal keys with one line

### After (Soft Enclave - Protected)

```javascript
// ✅ Protected by 4 security layers
import { createEnclave } from '@fastnear/soft-enclave';
import { KeyStore } from '@fastnear/soft-enclave/keystore';

// One-time setup
const enclave = createEnclave();
await enclave.initialize();

const keystore = new KeyStore();
await keystore.storeKey('account.testnet', privateKey);

// Sign transaction (keys never exposed to host)
const { result } = await keystore.signTransaction('account.testnet', tx);
```

**Attack surface**: Requires bypassing WebCrypto + SOP + sandbox + 50ms timing

### Migration Steps

1. **Install soft-enclave**

```bash
npm install @fastnear/soft-enclave
```

2. **Set up enclave server** (see Installation section)

3. **Migrate keys to keystore**

```javascript
// Read existing keys from localStorage
const accounts = Object.keys(localStorage)
  .filter(key => key.endsWith('_privateKey'));

// Migrate to keystore
const keystore = new KeyStore();
for (const key of accounts) {
  const accountId = key.replace('_privateKey', '');
  const privateKey = localStorage.getItem(key);

  await keystore.storeKey(accountId, privateKey);

  // Remove from localStorage after successful migration
  localStorage.removeItem(key);
}

console.log('Migrated', accounts.length, 'keys to keystore');
```

4. **Update signing code**

```javascript
// OLD:
const privateKey = localStorage.getItem('account_privateKey');
const sig = signWithPrivateKey(privateKey, data);

// NEW:
const sig = await keystore.signData('account.testnet', data);
```

5. **Test thoroughly**

```javascript
// Verify keystore works
const testData = new Uint8Array([1, 2, 3, 4]);
const sig = await keystore.signData('account.testnet', testData);
console.log('✓ Keystore working:', sig.length === 64);
```

6. **Deploy with feature flag**

```javascript
const USE_SOFT_ENCLAVE = process.env.FEATURE_SOFT_ENCLAVE === 'true';

if (USE_SOFT_ENCLAVE) {
  return await keystore.signData(accountId, data);
} else {
  return signWithPrivateKey(localStorage.getItem(`${accountId}_privateKey`), data);
}
```

7. **Monitor metrics**

```javascript
setInterval(() => {
  const metrics = keystore.getMetrics();
  console.log('Keystore metrics:', {
    avgExposure: metrics.averageKeyExposureMs,
    operations: metrics.totalOperations
  });

  // Alert if unusual
  if (metrics.averageKeyExposureMs > 100) {
    alert('Unusual key exposure times detected');
  }
}, 60000); // Every minute
```

---

## API Reference Summary

### `createEnclave(options?)`

Create enclave instance.

```typescript
function createEnclave(options?: {
  mode?: EnclaveMode.IFRAME | EnclaveMode.WORKER;
  enclaveOrigin?: string;
  workerUrl?: string;
}): Enclave
```

**Example**:

```javascript
const enclave = createEnclave(); // iframe backend, default origin
```

### `enclave.initialize()`

Initialize secure channel.

```typescript
async function initialize(): Promise<void>
```

**Example**:

```javascript
await enclave.initialize();
```

### `enclave.execute(code, context?)`

Execute sandboxed code.

```typescript
async function execute(
  code: string,
  context?: Record<string, any>
): Promise<{
  result: any;
  metrics: {
    keyExposureMs: number;
    totalDurationMs: number;
    memoryZeroed: boolean;
  }
}>
```

**Example**:

```javascript
const { result, metrics } = await enclave.execute('40 + 2');
```

### `keystore.storeKey(accountId, privateKey, metadata?)`

Store encrypted key.

```typescript
async function storeKey(
  accountId: string,
  privateKey: string,
  metadata?: Record<string, any>
): Promise<void>
```

### `keystore.signData(accountId, data)`

Sign data with stored key.

```typescript
async function signData(
  accountId: string,
  data: Uint8Array
): Promise<Uint8Array>
```

### Full API Documentation

See [API.md](./API.md) for complete reference.

---

## Examples

### Demo Applications

- **Main Demo**: [`http://localhost:3000/`](http://localhost:3000/) - Interactive playground
- **Security Tests**: [`/demo/test-runner.html`](http://localhost:3000/demo/test-runner.html) - Visual security property verification
- **Persistence Demo**: [`/examples/persistence-demo.html`](http://localhost:3000/examples/persistence-demo.html) - Key custody + storage
- **NEAR Counter**: [`/demo/examples/near-counter.html`](http://localhost:3000/demo/examples/near-counter.html) - Simulated smart contract
- **Mode Comparison**: [`/demo/examples/mode-comparison.html`](http://localhost:3000/demo/examples/mode-comparison.html) - iframe vs Worker

### Code Examples

```bash
# Clone repository
git clone https://github.com/fastnear/soft-enclave.git
cd soft-enclave

# Run examples
yarn install
yarn build
yarn dev

# Open http://localhost:3000 in browser
```

### Reference Implementations

- **Basic Integration**: `demo/demo.js`
- **Keystore Usage**: `examples/persistence-demo.html`
- **NEAR Signing**: `packages/near/src/enclave/near-tx.ts`

---

## Need Help?

- **Documentation**: [README.md](../README.md)
- **Threat Model**: [THREAT_MODEL.md](./THREAT_MODEL.md)
- **Architecture**: [ARCHITECTURE.md](./ARCHITECTURE.md)
- **Issues**: [GitHub Issues](https://github.com/fastnear/soft-enclave/issues)

---

**You're ready to integrate!** Follow the Quick Start, configure CSP correctly, and you'll have a working enclave in < 30 minutes. 🎉
