# Threat Model - Honest Security Assessment

**What soft enclave defends against, what it doesn't, and why**

## Core Principle: Honesty Over Marketing

This project **does not** claim to provide "secure enclave" capabilities equivalent to hardware TEEs. We provide a **pragmatic security improvement** over localStorage through defense-in-depth.

##Attack Surface Reduction

### Before (localStorage)

```javascript
// Vulnerable: Private key in plaintext, accessible to any script
localStorage.setItem('privateKey', keyHex);

// Attack vectors:
// 1. XSS → document.cookie / localStorage access
// 2. Extensions → chrome.storage access
// 3. Malicious scripts → direct memory access
// 4. MITM → plaintext transmission (if leaked)
```

**Attack complexity**: LOW (single XSS = game over)

### After (Soft Enclave)

```javascript
// Key encrypted, cross-origin, ephemeral exposure
const enclave = createEnclave({ mode: 'worker' });
await enclave.initialize();
const sig = await enclave.signTransaction(encryptedKey, tx);
// Key exposed in plaintext for ~40ms in isolated context
```

**Attack complexity**: MEDIUM-HIGH (must bypass multiple layers)

To extract keys, attacker must:
1. **Compromise WebCrypto** (browser internal)
2. **Bypass SOP** (access cross-origin memory)
3. **Time attack precisely** (~40ms window)
4. **Locate in WASM heap** (no fixed addresses)
5. **Bypass memory zeroing** (explicit cleanup)

## Threat Matrix

### ✅ Strong Protection (Primary Use Cases)

#### 1. XSS on Host Origin

**Attack**: Malicious script injected into main page tries to steal keys

**Defense**:
- Keys encrypted with non-extractable WebCrypto key
- Cross-origin isolation (SOP barrier)
- Enclave never returns plaintext keys
- AAD prevents ciphertext manipulation

**Effectiveness**: ⭐⭐⭐⭐⭐

#### 2. Malicious Guest Code

**Attack**: Untrusted code executed in enclave tries to exfiltrate data

**Defense**:
- QuickJS sandbox (memory isolation)
- No network access in enclave
- Frozen intrinsics (no Date, Math.random)
- Egress guard blocks plaintext (iframe backend)

**Effectiveness**: ⭐⭐⭐⭐⭐

#### 3. Replay Attacks

**Attack**: Attacker captures encrypted message and replays it

**Defense**:
- IV deduplication (seen cache)
- Sequence number validation
- Context binding (session specific)

**Effectiveness**: ⭐⭐⭐⭐⭐

#### 4. MITM Between Host and Enclave

**Attack**: Network attacker tries to intercept messages

**Defense**:
- Authenticated encryption (AES-GCM with AAD)
- Context binding includes origins
- Session keys ephemeral (per-session ECDH)

**Effectiveness**: ⭐⭐⭐⭐⭐

### ⚠️ Partial Protection

#### 5. Basic Browser Extensions

**Attack**: Extension with limited permissions tries to access keys

**Defense**:
- Cross-origin isolation (limited extension access)
- Non-extractable keys (WebCrypto protection)
- No DOM/cookie exposure

**Effectiveness**: ⭐⭐⭐ (depends on extension capabilities)

**Limitations**:
- Extensions with `debugger` permission can inspect workers
- Extensions can hook WebCrypto APIs
- No defense against sophisticated extensions

#### 6. Timing Side-Channels

**Attack**: Measure operation timing to infer key bits

**Defense**:
- Narrow exposure window (~40ms)
- Encrypted messages (constant-time AES-GCM in WebCrypto)

**Effectiveness**: ⭐⭐

**Limitations**:
- JavaScript crypto not constant-time across engines
- Speculative execution attacks (Spectre-class)
- Shared-memory timing channels

### ❌ No Protection (Out of Scope)

#### 7. Compromised Browser

**Attack**: Browser process itself is compromised

**Defense**: None

**Rationale**: Browser is our TCB (Trusted Computing Base). If browser is compromised, all web security is void.

**Mitigation**: Use hardware wallet for high-value operations

#### 8. DevTools Access

**Attack**: User (or attacker with physical access) uses DevTools

**Defense**: None (by design)

**Rationale**: User choice. Users with DevTools can inspect everything.

**Mitigation**: Warn users about DevTools risks

#### 9. OS-Level Malware

**Attack**: Malware with OS privileges scans memory

**Defense**: None

**Rationale**: OS-level attacks bypass all browser security.

**Mitigation**: OS security hygiene, hardware wallets for high-value

#### 10. Sophisticated Browser Extensions

**Attack**: Extension with debugger/webRequest permissions

**Defense**: Minimal

**Rationale**: Such extensions can hook crypto APIs and inspect workers.

**Mitigation**: Warn users about extension risks, use hardware wallet

## Security Tier Recommendations

| Threat Level | Transaction Value | Recommended Tier | Implementation |
|--------------|-------------------|------------------|----------------|
| **Low** | < $100 | Tier 1 | In-page sandbox + WebCrypto |
| **Medium** | $100 - $10K | **Tier 2** | **Soft Enclave (this project)** |
| **High** | $10K - $100K | Tier 3 | TEE backend (SGX/SEV/Nitro) |
| **Critical** | > $100K | Tier 4 | Hardware wallet (Ledger/Trezor) |

## Risk Assessment

### Daily Transactions ($10-$100)

**Threat**: XSS, accidental script injection
**Recommended**: Soft Enclave (worker backend)
**Rationale**: Significant security improvement over localStorage with minimal UX friction

### Moderate Transactions ($100-$10K)

**Threat**: Targeted XSS, malicious extensions (basic)
**Recommended**: Soft Enclave (iframe backend with egress guard)
**Rationale**: Defense-in-depth with visible security properties

### High-Value Transactions ($10K-$100K)

**Threat**: Sophisticated attacks, persistent threats
**Recommended**: TEE backend (future) or hardware wallet
**Rationale**: Requires hardware-backed attestation

### Treasury Operations (> $100K)

**Threat**: Nation-state actors, insider threats
**Recommended**: Hardware wallet only
**Rationale**: Requires dedicated secure element

## Attack Scenarios & Responses

### Scenario 1: XSS Injection

```
Attack: eval(maliciousCode) executed on host page
Goal: Steal private keys
```

**Defense**:
1. Keys are encrypted (WebCrypto non-extractable key)
2. Cross-origin isolation prevents memory access
3. Enclave never returns plaintext keys
4. AAD prevents ciphertext reuse

**Result**: ✅ PROTECTED

### Scenario 2: Malicious Extension

```
Attack: Chrome extension with "debugger" permission
Goal: Inspect worker memory
```

**Defense**:
1. Cross-origin worker (limited extension access)
2. Ephemeral key exposure (~40ms window)
3. Memory zeroing after operation

**Result**: ⚠️ PARTIALLY PROTECTED (narrow attack window)

### Scenario 3: Compromised Browser

```
Attack: Browser process has malware
Goal: Full memory access
```

**Defense**: None

**Result**: ❌ NOT PROTECTED

**Recommendation**: Use hardware wallet

### Scenario 4: Replay Attack

```
Attack: Capture encrypted message, replay later
Goal: Re-execute operation
```

**Defense**:
1. IV deduplication cache (max 4096 seen IVs)
2. Sequence number validation
3. Session-specific keys

**Result**: ✅ PROTECTED

### Scenario 5: DevTools Inspection

```
Attack: User opens DevTools, inspects worker
Goal: View key material
```

**Defense**: Warning in UI

**Result**: ❌ NOT PROTECTED (by design)

**Rationale**: User's choice to inspect their own browser

## Comparison with Alternatives

| Property | localStorage | Soft Enclave | Hardware TEE | Hardware Wallet |
|----------|--------------|--------------|--------------|-----------------|
| **XSS protection** | ✗ | ✓✓✓ | ✓✓✓ | ✓✓✓ |
| **Extension resistance** | ✗ | ✓ | ✓✓ | ✓✓✓ |
| **OS malware** | ✗ | ✗ | ✓ | ✓✓✓ |
| **Physical access** | ✗ | ✗ | ✓ | ✓✓✓ |
| **Remote attestation** | ✗ | ✗ | ✓✓✓ | ✓✓✓ |
| **Ubiquity** | ✓✓✓ | ✓✓✓ | ✓ | ✗ |
| **UX friction** | ✓✓✓ | ✓✓ | ✓ | ✗ |
| **Cost** | Free | Free | $$$ | $50-$200 |

## Known Limitations

### 1. JavaScript Crypto Not Constant-Time

**Issue**: JavaScript operations may leak timing information

**Impact**: Theoretical side-channel attacks

**Mitigation**: Use WebCrypto (browser implements constant-time), minimize JS crypto operations

### 2. Speculative Execution (Spectre-Class)

**Issue**: CPU speculation may leak cross-origin data

**Impact**: Sophisticated attackers could extract keys

**Mitigation**: Browsers implement mitigations (Site Isolation), narrow exposure window

### 3. Shared-Memory Timing Channels

**Issue**: SharedArrayBuffer + high-precision timers enable timing attacks

**Impact**: Could measure operation timing across origins

**Mitigation**: We don't use SharedArrayBuffer, browsers limit timer precision

### 4. Browser Extension Ecosystem

**Issue**: Extensions can have powerful permissions

**Impact**: Malicious extensions could compromise security

**Mitigation**: Warn users, recommend extension review, use hardware wallet for high-value

## Security Recommendations

### For Users

- ✅ Use soft enclave for daily transactions (< $10K)
- ✅ Review browser extensions regularly
- ✅ Use hardware wallet for high-value transactions
- ❌ Don't install untrusted browser extensions
- ❌ Don't use soft enclave on compromised systems

### For Developers

- ✅ Understand the threat model (don't oversell)
- ✅ Implement transaction value thresholds
- ✅ Provide clear upgrade path to hardware wallets
- ✅ Monitor key exposure metrics (< 100ms)
- ❌ Don't claim "secure enclave" capabilities
- ❌ Don't use for treasury operations (> $100K)

## Future Improvements

### Near-Term
- [ ] TEE backend integration (SGX/SEV/Nitro)
- [ ] Remote attestation support
- [ ] Hardware wallet integration
- [ ] Side-channel hardening

### Long-Term
- [ ] Post-quantum cryptography (HPKE with ML-KEM)
- [ ] Formal verification of protocol
- [ ] Browser API standardization

## Responsible Disclosure

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email security@near.org with details
3. Allow 90 days for patch development
4. Coordinate public disclosure

## References

- [MDN: Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
- [Web Crypto API Security](https://www.w3.org/TR/WebCryptoAPI/#security)
- [Site Isolation (Spectre Mitigation)](https://www.chromium.org/Home/chromium-security/site-isolation/)
- [Browser Extension Security](https://developer.chrome.com/docs/extensions/mv3/security/)
