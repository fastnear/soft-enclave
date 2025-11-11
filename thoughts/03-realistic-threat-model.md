# Realistic Threat Model & Security Architecture

## Honest Assessment: What We Can Actually Achieve

### Tier 1: Protection Against Malicious Guest Code ✓✓✓
**Status**: Excellent - This is the primary value proposition

```javascript
// Running untrusted code safely
const untrustedCode = `
  process.exit(1);           // Won't work - no process
  require('fs');             // Won't work - no require
  fetch('evil.com');         // Only if not exposed
  while(true) {}             // Can timeout/limit
`;

// QuickJS-WASM provides strong isolation
quickjs.evalCode(untrustedCode); // Safely contained
```

**Use Cases**:
- Execute user-provided smart contract simulation code
- Run plugins/extensions safely
- Sandbox third-party scripts

### Tier 2: Improved localStorage Alternative ✓✓
**Status**: Moderate - Better than plaintext storage

**Attack Window Narrowing**:
```javascript
// BAD: Traditional approach
localStorage.setItem('privateKey', key); // Persistent, easy target for XSS

// BETTER: Ephemeral computation in WASM
async function signTransaction(encryptedKey, txData) {
  const start = performance.now();

  // Key only exists in plaintext for ~50ms in WASM memory
  const signature = await quickjs.evalCode(`
    const key = decrypt(encryptedKey);
    const sig = sign(key, txData);
    key.fill(0);  // Explicit zeroing
    encrypt(sig);
  `);

  console.log(`Key exposed for ${performance.now() - start}ms`);
  return signature;
}
```

**Security Improvement**:
- Attacker needs precise timing
- Must locate key in WASM heap during narrow window
- Better than persistent localStorage
- Not perfect, but raises the bar

### Tier 3: Confidentiality from Sophisticated Attackers ✗
**Status**: Limited - Not a hardware TEE

**Honest Limitations**:
- Host JS can obtain WebAssembly.Memory handle
- Browser DevTools can inspect memory
- No hardware attestation
- No protection against compromised browser

## Hybrid Architecture: WebCrypto + WASM + Cross-Origin

### Strategy: Defense in Depth

```javascript
/**
 * Three-Layer Security Model:
 * 1. WebCrypto non-extractable keys (primary)
 * 2. Cross-origin WASM isolation (secondary)
 * 3. Ephemeral computation (tertiary)
 */

class HybridSecureEnclave {
  // Layer 1: Non-extractable WebCrypto key
  private cryptoKey: CryptoKey; // Browser prevents extraction

  // Layer 2: Cross-origin worker (SOP isolation)
  private enclaveWorker: Worker;

  async initialize() {
    // Generate non-extractable master key
    this.cryptoKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // NOT extractable - stays in browser's secure storage
      ['encrypt', 'decrypt']
    );

    // Initialize cross-origin worker with QuickJS
    this.enclaveWorker = new Worker('https://enclave.example.com/worker.js');
  }

  async secureOperation(sensitiveData: any) {
    // Layer 1: Encrypt with non-extractable key
    const encrypted = await this.encryptWithWebCrypto(sensitiveData);

    // Layer 2: Send to cross-origin worker (SOP prevents memory access)
    const result = await this.enclaveWorker.postMessage({
      type: 'EXECUTE',
      payload: encrypted  // Still encrypted when crossing boundary
    });

    // Layer 3: WASM processes encrypted data, returns encrypted result
    // Final decrypt with non-extractable key
    return this.decryptWithWebCrypto(result);
  }

  private async encryptWithWebCrypto(data: any): Promise<EncryptedPayload> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.cryptoKey,  // Non-extractable!
      new TextEncoder().encode(JSON.stringify(data))
    );

    return { iv, ciphertext };
  }
}
```

### Attack Complexity Analysis

To extract sensitive data, attacker must:

1. **Compromise non-extractable WebCrypto key** (browser internal storage)
2. **Bypass same-origin policy** (get handle to cross-origin Memory)
3. **Time attack precisely** (during ~50ms computation window)
4. **Locate data in WASM heap** (no fixed addresses)
5. **Bypass memory zeroing** (explicit cleanup)

**Each layer independently raises the bar.**

## Practical Use Case: NEAR Wallet Key Management

### Scenario
User needs to sign NEAR transactions without exposing private key to:
- XSS vulnerabilities
- Malicious browser extensions (limited capability)
- Compromised third-party scripts

### Architecture

```javascript
// Host page (https://wallet.near.org)
class SecureNEARWallet {
  private enclave: HybridSecureEnclave;

  async signTransaction(tx: Transaction) {
    // User's key is encrypted at rest
    const encryptedKey = await this.getEncryptedKeyFromStorage();

    // Signing happens in enclave with ephemeral decryption
    const signature = await this.enclave.secureOperation({
      operation: 'SIGN_TRANSACTION',
      key: encryptedKey,
      transaction: tx
    });

    // Key existed in plaintext for ~50ms in cross-origin WASM
    return signature;
  }
}

// Worker (https://enclave-worker.near.org)
// - Different origin = SOP isolation
// - QuickJS-WASM for sandboxing
// - Ephemeral key handling
```

### Security Properties Achieved

✓ **Better than localStorage**: Key not persistently stored in plaintext
✓ **Better than sessionStorage**: Ephemeral + cross-origin isolation
✓ **Sandboxed execution**: QuickJS prevents malicious code escape
✓ **Multiple barriers**: Attacker must bypass 3+ independent mechanisms
✓ **Auditable**: Deterministic execution, verifiable on-chain

✗ **Not a hardware TEE**: No attestation, no hardware secrets
✗ **Not safe from DevTools**: User can inspect (but that's their choice)
✗ **Not safe from compromised browser**: OS-level malware can extract

## Deterministic Execution + On-Chain Verification

### Additional Security Model: Trust Through Verification

```javascript
/**
 * Even without perfect confidentiality, deterministic execution
 * enables fraud proofs and verification
 */

class VerifiableComputation {
  async executeWithCommitment(code: string, inputs: any) {
    // Execute in QuickJS (deterministic)
    const result = await quickjs.evalCode(code, inputs);

    // Commit to NEAR blockchain
    await near.call('commit_computation', {
      code_hash: sha256(code),
      input_hash: sha256(JSON.stringify(inputs)),
      result_hash: sha256(JSON.stringify(result)),
      timestamp: Date.now()
    });

    // Anyone can challenge within 24 hours
    // Re-execute and verify deterministically
  }

  async challenge(computation_id: string) {
    const original = await near.view('get_computation', { computation_id });

    // Re-execute deterministically
    const recomputed = await quickjs.evalCode(
      original.code,
      original.inputs
    );

    if (sha256(recomputed) !== original.result_hash) {
      // Fraud proof! Slash the committer
      await near.call('slash_fraudulent_computation', {
        computation_id,
        proof: recomputed
      });
    }
  }
}
```

**Security Property**: Don't need secrecy if execution is:
- Deterministic
- Verifiable
- Fraud-provable
- Economically secured (slashing)

## Implementation Focus

### 1. Ephemeral Computation Pattern
- Keys exist decrypted only during active operations
- Explicit memory zeroing after use
- Timing metrics to verify short exposure windows

### 2. Defense in Depth
- WebCrypto non-extractable keys as primary defense
- Cross-origin isolation via SOP
- WASM sandboxing for code execution
- Explicit cleanup and zeroing

### 3. Clear Threat Model Documentation
```javascript
/**
 * THREAT MODEL
 *
 * Defends Against:
 * ✓ XSS attacks attempting to steal localStorage
 * ✓ Unsophisticated browser extensions
 * ✓ Malicious guest code execution
 * ✓ Timing attacks (limited window)
 *
 * Does NOT Defend Against:
 * ✗ Sophisticated attackers with persistent browser access
 * ✗ Compromised browser process
 * ✗ User with DevTools (by design)
 * ✗ Hardware attacks (Spectre, etc.)
 * ✗ OS-level malware
 *
 * Use Case Guidance:
 * ✓ Good for: Daily transactions, low-to-medium value
 * ✗ Not for: Large treasury management, high-value custody
 * → For high-stakes: Use hardware wallet or TEE-backed solution
 */
```

### 4. Progressive Enhancement
```javascript
enum SecurityLevel {
  BASIC = 'localStorage',           // Convenience only
  IMPROVED = 'wasm-ephemeral',      // This implementation
  STRONG = 'hardware-tee',          // Ledger/SGX/etc
}

class AdaptiveSecureWallet {
  async signTransaction(tx: Transaction, requiredLevel: SecurityLevel) {
    if (tx.value > THRESHOLD_HIGH && requiredLevel < SecurityLevel.STRONG) {
      throw new Error('High-value transaction requires hardware wallet');
    }

    switch (requiredLevel) {
      case SecurityLevel.IMPROVED:
        return this.hybridEnclave.sign(tx);
      case SecurityLevel.STRONG:
        return this.hardwareWallet.sign(tx);
    }
  }
}
```

## Next Steps: Honest Implementation

1. **Build hybrid WebCrypto + Cross-Origin + WASM system**
2. **Measure attack windows** (how long keys are exposed)
3. **Document realistic threat model** (what it does/doesn't protect)
4. **Implement explicit memory zeroing and cleanup**
5. **Create comparative benchmarks** (vs localStorage, vs sessionStorage)
6. **Add optional hardware TEE backend for high-stakes operations**

## Success Criteria

This implementation succeeds if:
- It's measurably more secure than localStorage
- It has clear, honest documentation about limitations
- It provides practical security improvements for common threats
- It offers progressive enhancement path to hardware security
- It doesn't claim to be more than it is
