# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Browser-based secure enclave using QuickJS-WASM with cross-origin isolation and encrypted communication. This project implements a **realistic, honest** approach to improving browser security through defense-in-depth.

**Critical Context:** This is NOT a hardware TEE and doesn't claim to be. It provides **practical security improvements** over localStorage through multiple independent layers while being honest about limitations.

## Key Architecture Principles

### 1. Honest Threat Model

The entire architecture is built around **what we can actually achieve** in a browser:

**Tier 1 (Excellent):** Protection against malicious guest code
- QuickJS-WASM sandboxing prevents code escape
- No access to host globals (window, document, fetch)

**Tier 2 (Moderate):** Improved over localStorage
- XSS attacks face multiple barriers
- Ephemeral key exposure (~30-50ms window)
- Explicit memory zeroing

**Tier 3 (Limited):** Confidentiality from sophisticated attackers
- Not achieved, not claimed
- Documented clearly in all materials

### 2. Defense-in-Depth Layers

Four independent security layers:
1. **WebCrypto non-extractable keys** - Primary defense
2. **Cross-origin worker** - SOP isolation barrier
3. **QuickJS-WASM sandbox** - Execution isolation
4. **Ephemeral computation** - Time-limited exposure

Attacker must bypass ALL layers simultaneously.

### 3. Measurable Security

Every operation tracks:
- Key exposure duration (target: <50ms)
- Memory zeroing confirmation
- Total operation duration

These metrics are exposed to users and logged.

## Dual-Backend Architecture (MAJOR UPDATE)

**This project now supports TWO isolation backends:**

### iframe Backend (Default - CSP-Compatible)
- **Location**: `src/backends/iframe/`
- **Isolation**: Cross-origin iframe + MessageChannel
- **Protocol**: Simple ECDH+HKDF (default), Advanced available
- **Entry**: Port 3010 (npm run serve:iframe)
- **Features**: Explicit egress guard, works with strict CSP, easier debugging
- **Best for**: Production (CSP-compatible), development, security demos

### Worker Backend (Requires CSP Relaxation)
- **Location**: `src/backends/worker-backend.js`
- **Isolation**: Cross-origin Web Worker via Blob URL
- **Protocol**: Advanced (v1.1) with transcript binding
- **Entry**: Port 3010 (npm run serve:enclave)
- **CSP Requirement**: Must allow `worker-src blob:` or `worker-src http://localhost:3010 blob:`
- **Best for**: Environments with relaxed CSP, performance-critical scenarios

### Unified Factory API

Both backends use the same interface via `createEnclave()`:

```javascript
import { createEnclave, EnclaveMode } from '@fastnear/soft-enclave';

// iframe backend (default - CSP-compatible)
const enclave = createEnclave();

// Worker backend (requires blob: in CSP)
const enclave = createEnclave({
  mode: EnclaveMode.WORKER
});

// Both have same API:
await enclave.initialize();
const { result } = await enclave.execute('40 + 2');
```

## Project Structure (Updated)

```
soft-enclave/
├── src/
│   ├── core/                     # Unified API
│   │   ├── enclave-base.js       # Abstract base class
│   │   └── enclave-factory.js    # Factory with tier recommendations
│   ├── backends/                 # Isolation backends
│   │   ├── worker-backend.js     # Web Worker implementation
│   │   └── iframe/               # iframe implementation (from near-outlayer)
│   │       ├── host/             # Host-side (EnclaveClient)
│   │       └── enclave/          # Enclave-side (egress guard, QuickJS)
│   ├── near/                     # NEAR integration
│   │   ├── storage-shim.js       # near.storageRead/Write/log
│   │   └── deterministic-prelude.js  # LCG PRNG, frozen intrinsics
│   └── shared/                   # Shared utilities
│       ├── crypto-protocol.js    # Advanced protocol (v1.1)
│       ├── message-types.js      # Message type definitions
│       ├── keystore.ts           # WebCrypto key custody (Phase 3)
│       └── storage.ts            # Encrypted IndexedDB storage (Phase 3)
├── demo/                         # Demos
│   ├── test-runner.html         # Visual security test runner (4 tests)
│   └── examples/                # NEAR examples
│       ├── near-counter.html    # Stateful counter contract
│       └── mode-comparison.html # Worker vs iframe comparison
├── examples/                     # Usage examples
│   └── persistence-demo.html    # Key custody + encrypted storage demo
├── test/                         # Tests (Vitest)
├── docs/                         # Documentation
│   ├── ARCHITECTURE.md          # Tier model, backends, protocols
│   ├── THREAT_MODEL.md          # Honest security assessment
│   └── PERSISTENCE.md           # Key custody and storage architecture
└── thoughts/                     # Research
```

## Architecture Decisions

### ADR-001: Dual Backend Support

**Decision**: Support both Worker and iframe backends through unified API

**Rationale**:
- Worker backend provides cleanest production security model
- iframe backend (from near-outlayer) is battle-tested and proven
- Unified API allows users to choose based on their needs
- Easier debugging with iframe (inspector access)
- Better security demonstrations (explicit egress guard)

**Implementation**: Abstract base class `EnclaveBase` with backend-specific subclasses

### ADR-002: Keep Advanced Crypto Protocol

**Decision**: Maintain advanced protocol (v1.1) for worker backend

**Rationale**:
- Transcript binding increases security
- Strict sequence validation prevents subtle attacks
- Message size limits provide DoS protection
- Can coexist with simple protocol (iframe backend)

**Trade-off**: Slightly more complex, but measurably more secure

### ADR-003: NEAR Integration Layer

**Decision**: Separate NEAR-specific code into `/src/near/`

**Rationale**:
- Storage shim (`near.storageRead/Write/log`) enables contract execution
- Deterministic prelude (LCG PRNG, frozen intrinsics) ensures reproducibility
- Clean separation allows non-NEAR usage
- Directly ported from near-outlayer for compatibility

**Files**: `storage-shim.js`, `deterministic-prelude.js`

### ADR-004: Visual Test Runner

**Decision**: Create browser-based test runner with visual feedback

**Rationale**:
- Proves security properties to users (not just developers)
- Shows 4 key tests: Basic execution, SOP barrier, Replay protection, Context binding
- Works with both backends
- Better for demos and presentations than unit tests

**Location**: `demo/test-runner.html`

### ADR-005: Persistence Architecture (Phase 3)

**Decision**: Implement WebCrypto-based key custody and encrypted storage

**Rationale**:
- **Security concern addressed**: Users worried about key vulnerability in browser storage
- **Defense-in-depth**: Four independent security layers
  1. WebCrypto non-extractable keys (browser enforced)
  2. Key wrapping (AES-GCM encryption before IndexedDB)
  3. Ephemeral unwrapping (keys decrypted only during ~30-50ms operations)
  4. Memory zeroing (best-effort cleanup)
- **Honest security model**: Explicitly documented as NOT hardware TEE
- **Measurable security**: Timing metrics for all key operations
- **Progressive enhancement**: Clear upgrade path to hardware wallets

**Implementation**:
- `packages/shared/src/keystore.ts` - NEAR key custody
- `packages/shared/src/storage.ts` - General encrypted storage
- `examples/persistence-demo.html` - Interactive demonstration
- `docs/PERSISTENCE.md` - Complete architecture documentation

**Threat Model Tiers**:
- ✅ **Tier 1 (Excellent)**: Protection against malicious guest code
- ✅ **Tier 2 (Moderate)**: Improvement over localStorage (XSS faces multiple barriers)
- ❌ **Tier 3 (Limited)**: NOT protected against sophisticated attackers

**Key Features**:
- Non-extractable master keys (browser enforced, cannot be exported)
- Ed25519 private key wrapping with AES-GCM
- Ephemeral key exposure windows (<50ms target)
- Security metrics tracking (average exposure time, operation count)
- Multi-account management
- Encrypted application state storage

**When to Use**:
- ✅ Development and testing
- ✅ Convenience/user experience for low-value keys
- ✅ User onboarding flows
- ❌ High-value keys (use hardware wallets)
- ❌ Treasury management
- ❌ Validator keys

**Dependencies**:
- `idb` (^8.0.0) - Promise-based IndexedDB wrapper
- `tweetnacl` (^1.0.3) - Ed25519 signing
- WebCrypto API (browser built-in)

### ADR-006: Immutable Global Surfaces Over Primordial Freezing

**Decision**: Use `Object.defineProperty(globalThis, 'X', { configurable: false, writable: false })` to harden specific API surfaces instead of freezing JavaScript primordials (Object.prototype, Array.prototype, etc.)

**Rationale**:
- **Test compatibility**: Freezing primordials conflicted with Vitest and build tool internals, causing unhandled errors during module collection
- **Zero production usage**: No production code used `freezePrimordials` option - it was test-only
- **Already established pattern**: The tsup.config.ts already uses this approach for the `SoftEnclave` global
- **Clearer security model**: "Our API is immutable" vs. "JavaScript is immutable" - more honest about what we can guarantee
- **Simpler implementation**: Less code, fewer edge cases, easier to maintain
- **Aligned with threat model**: In browser environments, hardening specific API surfaces provides practical security without fighting the runtime

**Implementation**:
- `packages/shared/src/deterministic-shims.ts`:
  - Added `hardenGlobalSurface(name: string)` function
  - Removed `freezePrimordials()` function
  - Updated `hardenRealm()` signature: `hardenGlobals: string[]` instead of `freezePrimordials: boolean`
  - Updated return type: `hardenedGlobals: string[]` instead of `frozenPrimordials: boolean`
- `packages/near/src/storage-shim.ts`:
  - Applied hardening pattern to `near` global
- `test/deterministic-shims.test.js`:
  - Replaced 5 primordial freezing tests with 4 global surface immutability tests
  - New suite: "Security: Global Surface Immutability"

**Pattern**:
```javascript
Object.defineProperty(globalThis, 'near', {
  value: near,
  enumerable: true,
  configurable: false,  // Cannot be deleted or redefined
  writable: false       // Cannot be reassigned
});
```

**Benefits**:
- ✅ Clean test runs (exit code 0, no unhandled errors)
- ✅ Works with all build tools and test runners
- ✅ Same security properties for our API surfaces
- ✅ More maintainable and easier to explain
- ✅ Honest about browser security limitations

**Trade-offs**:
- Does not prevent modification of built-in prototypes (but neither did the old approach in practice - it just broke tests)
- Focuses on protecting our APIs rather than the entire JavaScript realm
- More aligned with realistic browser security model

### When to Use Which Backend

| Use Case | Backend | Why |
|----------|---------|-----|
| Production with strict CSP | **iframe** | Works without CSP modifications (recommended) |
| Development/debugging | **iframe** | Better DevTools access, visual egress guard |
| Security demonstrations | **iframe** | Explicit runtime guards, easier inspection |
| Production with relaxed CSP | Worker | Slightly lower overhead (requires `blob:` in CSP) |
| Performance-critical | Worker | Minimal serialization overhead |

## Development Commands (Updated)

```bash
# Install dependencies
npm install

# Development - Worker Backend (requires 2 terminals)
npm run dev              # Terminal 1: Host app (localhost:3000)
npm run serve:enclave    # Terminal 2: Worker (localhost:3010)

# Development - iframe Backend (requires 2 terminals)
npm run dev              # Terminal 1: Host app (localhost:3000)
npm run serve:iframe     # Terminal 2: iframe enclave (localhost:3010)

# Testing
npm test                 # Run all tests
npm run test:ci          # CI test suite (excludes experimental)
npm run test:security    # Security-focused tests only
RUN_HPKE=1 npm test      # Include experimental HPKE tests

# Build
npm run build           # Build for production
npm run preview         # Preview production build
```

## CSP Configuration Requirements

### iframe Backend (Default)

The iframe backend requires specific Content Security Policy (CSP) directives to allow cross-origin iframe embedding. These are pre-configured in `vite.config.js`:

**Required CSP Directives:**
```javascript
"frame-src 'self' http://localhost:3010"  // Allow enclave iframe (port 3010 = host port + 10)
"child-src 'self' http://localhost:3010"  // Legacy fallback
```

**Verification:**
```bash
# Check host CSP
curl -sI http://localhost:3000 | grep -i "content-security-policy"

# Check enclave headers
curl -sI http://localhost:3010 | egrep -i "cross-origin|content-security-policy"
```

**Expected headers:**
- **Host (localhost:3000)**: CSP includes `frame-src ... http://localhost:3010`
- **Enclave (localhost:3010)**:
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Embedder-Policy: require-corp`
  - `Content-Security-Policy: ... frame-ancestors http://localhost:3000`
  - `Content-Type: application/wasm` for .wasm files

**Production Configuration:**

In production, update CSP origins:
```javascript
// Host CSP (your main app)
"frame-src 'self' https://enclave.yourdomain.com"
"child-src 'self' https://enclave.yourdomain.com"

// Enclave CSP (enclave-server.js)
process.env.HOST_ORIGIN = 'https://yourdomain.com'
```

**Common Issues:**

1. **"Refused to frame ... violates CSP"** → Missing `frame-src` in host CSP
2. **"Wasm instantiate aborted"** → Check Content-Type: application/wasm on .wasm files
3. **"Cross-Origin-Embedder-Policy block"** → Ensure enclave has `Cross-Origin-Resource-Policy: cross-origin`

### Worker Backend (Requires CSP Relaxation)

The worker backend requires `blob:` in CSP:
```javascript
"worker-src http://localhost:3010 blob:"  // Required for Blob URL loading
```

This is **stricter** than iframe backend, hence iframe is the default.

## Critical Implementation Details

### Worker Cannot Receive WebAssembly.Module Cross-Origin

**IMPORTANT:** Since Chrome 95, `WebAssembly.Module` cannot be sent via `postMessage` cross-origin.

**Solution:** Load QuickJS-WASM directly in the worker:

```javascript
// In enclave-worker.js
import { newQuickJSWASMModule } from 'quickjs-emscripten';
const quickjs = await newQuickJSWASMModule();
```

**Never do this:**
```javascript
// Host (WRONG - will fail)
const quickjs = await newQuickJSWASMModule();
worker.postMessage({ quickjs }); // DataCloneError!
```

### Ephemeral Computation Pattern

The core security improvement comes from narrow exposure windows:

```javascript
// Key exists in plaintext ONLY during this operation
const execution = await measureTiming(async () => {
  return await this.executeInQuickJS(code, context);
});

// Typical duration: 30-50ms
// After this, memory is disposed/zeroed
```

This makes extraction attacks require:
- Precise timing (narrow window)
- Knowledge of memory layout
- Active exploitation during operation
- Bypassing all other layers

### Non-Extractable Keys

```javascript
// Master key CANNOT be exported
this.masterKey = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  false, // NOT extractable - critical!
  ['encrypt', 'decrypt']
);
```

This is enforced by the browser itself, not our code.

### Session Key Derivation

Host and worker use ECDH to derive a shared session key:

```javascript
// Both sides generate ephemeral ECDH key pairs
// Exchange public keys
// Derive same shared AES-GCM key
// Use for all subsequent communication
```

Session key is also non-extractable after derivation.

## Testing Strategy

### Test Suites

**Core test suites** (run in CI):
- `yarn test:ci` - All unit and security tests (146 tests)
- `yarn test:security` - Egress guard, channel security, deterministic shims
- `yarn test:bundle` - IIFE bundle integration tests (validates production artifacts)

**Optional test suites** (gated by environment variables):
- `yarn test:e2e` - End-to-end integration tests (requires `RUN_E2E=1`)
- `yarn test:hpke` - Experimental HPKE protocol tests (requires `RUN_HPKE=1`)

### Crypto Protocol Tests

Test all encryption/decryption operations:
- Key generation (extractable vs non-extractable)
- Encrypt/decrypt roundtrip
- ECDH key exchange
- Serialization for postMessage

**Run:** `yarn test test/crypto-protocol.test.js`

### IIFE Bundle Tests

Test actual distribution artifacts (not just source):
- Global hardening (`configurable: false`)
- Expected API surface exposed
- No unintended global leaks
- Bundle size and load performance
- Source maps and version banners

**Run:** `yarn test:bundle` (builds packages first, then tests IIFE artifacts)

### Isolation Tests

Verify security properties:
- Guest code cannot access host globals
- Key exposure windows are <100ms
- Deterministic execution
- Memory zeroing

**Note:** Some tests require a running worker and are skipped by default.

### Test Infrastructure

**Scoped Console Filtering** (`test/helpers/console.ts`):
- `muteConsoleErrors(patterns)` - Filters expected error patterns without masking real errors
- `muteConsoleWarns(patterns)` - Filters expected warning patterns
- Uses Vitest's `vi.spyOn()` for proper scoped mocking
- Avoids global console reassignment
- Preserves unexpected errors for debugging

```javascript
import { muteConsoleErrors } from './helpers/console';

beforeAll(() => {
  const restore = muteConsoleErrors([
    /expected pattern/i,
    'literal string to match'
  ]);
  // restore() when done
});
```

**Experimental Tests Gated**:
- HPKE protocol tests run only with `RUN_HPKE=1` environment variable
- Keeps CI output clean while preserving experimental work
- Run experimental tests: `RUN_HPKE=1 npm test test/hpke-protocol.test.js`

**Expected Errors**:
- Primordial freezing errors (`Cannot assign to read only property 'constructor'`) are expected
- Handled in `test/setup.js` and `vitest.config.js`
- Non-blocking, all tests pass despite these harmless errors

## Common Development Tasks

### Adding a New Operation Type

1. Add message type to `src/shared/message-types.js`:
   ```javascript
   export const MessageType = {
     // ...existing...
     MY_NEW_OPERATION: 'MY_NEW_OPERATION',
     MY_NEW_OPERATION_RESULT: 'MY_NEW_OPERATION_RESULT'
   };
   ```

2. Add handler in `src/enclave/enclave-worker.js`:
   ```javascript
   async handleMyNewOperation(message) {
     // Decrypt input
     // Execute in QuickJS
     // Measure timing
     // Encrypt result
     return { type: MessageType.MY_NEW_OPERATION_RESULT, ... };
   }
   ```

3. Add client method in `src/host/hybrid-enclave.js`:
   ```javascript
   async myNewOperation(data) {
     const encrypted = await encrypt(this.sessionKey, data);
     const response = await this.sendMessageAndWait({
       type: MessageType.MY_NEW_OPERATION,
       payload: serializePayload(encrypted)
     });
     return await decrypt(this.sessionKey, response.result);
   }
   ```

### Measuring Security Metrics

Always use `measureTiming` for sensitive operations:

```javascript
import { measureTiming } from '../shared/crypto-protocol.js';

const execution = await measureTiming(async () => {
  return await sensitiveOperation();
});

console.log(`Operation took ${execution.durationMs}ms`);
```

### Memory Zeroing

After using sensitive buffers:

```javascript
import { secureZero } from '../shared/crypto-protocol.js';

const keyBuffer = new Uint8Array(sensitiveData);
// ... use keyBuffer ...
secureZero(keyBuffer); // Fill with zeros
```

**Note:** JavaScript doesn't guarantee memory overwrite, but this is best-effort.

## Documentation Philosophy

All documentation (README, USAGE, threat model docs) follows these principles:

1. **Honest about limitations** - Never overclaim security properties
2. **Clear threat model** - Explicitly state what is/isn't defended
3. **Measurable claims** - All claims backed by metrics
4. **Progressive enhancement** - Guidance for upgrading to hardware security
5. **Use case appropriate** - Help users choose right security level

### When Writing Security Documentation

**DO:**
- State exact threat model
- Provide metrics (key exposure times, etc.)
- Compare to alternatives (localStorage, hardware wallets)
- Explain attack complexity
- Acknowledge limitations upfront

**DON'T:**
- Call it a "secure enclave" without qualifiers
- Claim hardware TEE properties
- Hide limitations in footnotes
- Overstate security guarantees

## Research Context

The `thoughts/` directory contains the research that led to this implementation:

- **01.txt**: Original analysis showing WASM doesn't provide memory confidentiality from host
- **02-architecture-design.md**: Initial architecture (before realistic threat model)
- **03-realistic-threat-model.md**: Honest assessment of what we can actually achieve

These documents are important context for understanding why this project takes its current approach.

## Dependencies

- **quickjs-emscripten@0.31.0**: QuickJS compiled to WebAssembly
  - Provides sandboxed JavaScript execution
  - Latest stable version (as of Nov 2024)
  - Must be loaded directly in worker (not sent via postMessage)

- **vite@5.0.0**: Build tool and dev server
  - Handles module bundling
  - Provides dev server with CORS headers
  - Configured for cross-origin isolation headers

- **vitest@1.0.0**: Test framework
  - Unit tests for crypto protocol
  - Integration tests for isolation properties

## Important Notes for Future Development

1. **Never overclaim security**: This is the most important principle. Every feature, every doc, every comment should be honest about limitations.

2. **Measure everything**: Key exposure times, operation durations, memory usage. If we can't measure it, we shouldn't claim it.

3. **Tests reflect threat model**: Tests verify what we claim to defend against, and document (via skips) what we don't.

4. **Progressive enhancement path**: Always provide guidance for when users should upgrade to hardware security.

5. **WebCrypto is the foundation**: Non-extractable keys are our strongest defense. Everything else is additional layers.

## Security Review Checklist

When reviewing PRs:

- [ ] Does it maintain honest threat model documentation?
- [ ] Are all security claims measurable?
- [ ] Does it use non-extractable keys where appropriate?
- [ ] Are timing metrics exposed?
- [ ] Is memory explicitly zeroed after sensitive operations?
- [ ] Does it avoid overclaiming security properties?
- [ ] Are limitations documented alongside features?

## Original Research Context

This project emerged from research analyzing WebAssembly memory isolation and security properties, particularly concerning QuickJS compiled to Wasm and whether it could serve as a "secure enclave" against the embedding page.

### Key Research Findings (from thoughts/01.txt)

1. **Memory Safety**: QuickJS-Wasm is memory-safe and isolated from the rest of the process (sandboxed by Wasm)
2. **Memory Confidentiality**: QuickJS-Wasm does NOT provide memory confidentiality from the embedding page by default
   - The host JavaScript can access the WebAssembly.Memory handle (via exports or imports)
   - With Emscripten defaults, memory is exported to JS
   - The quickjs-emscripten library exposes `mod.getWasmMemory()` API
3. **Security Model**: WebAssembly sandboxes modules to protect the host from modules, NOT to protect modules from the host

### Architecture Evolution

The research originally referenced a multi-layer architecture:
- L3: QuickJS layer
- L4: "Frozen Realm" that decrypts content

The analysis concluded that if L3/L4 runs in the same origin as the host page, memory confidentiality does not follow from Wasm isolation alone. This led to the current implementation using cross-origin worker/iframe boundaries with encrypted host↔guest payloads.

### Key Technical Learnings

- **WebAssembly.Memory**: The linear memory API exposes heap as ArrayBuffer to JavaScript
- **Emscripten Memory Modes**: Default exports memory; `-sIMPORTED_MEMORY=1` changes who creates Memory but doesn't add confidentiality
- **Cross-Origin Isolation**: The effective mitigation implemented in this project

These findings directly influenced the defense-in-depth approach taken in this implementation.

## References

- WebAssembly security: https://webassembly.org/docs/security/
- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- QuickJS-Emscripten: https://github.com/justjake/quickjs-emscripten
- Cross-Origin Isolation: https://web.dev/articles/coop-coep
- Original research in thoughts/01.txt
