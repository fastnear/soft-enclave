/**
 * Demo application for NEAR WASM Enclave
 */

import { createEnclave } from '@fastnear/soft-enclave';

class Demo {
  constructor() {
    this.enclave = null;
    this.metrics = {
      operations: 0,
      maxExposure: 0
    };

    this.initUI();
  }

  initUI() {
    // Initialize button
    document.getElementById('init-btn').addEventListener('click', () => {
      this.initialize();
    });

    // Execute Fibonacci button
    document.getElementById('fibonacci-btn').addEventListener('click', () => {
      this.tryFibonacciCode();
    });

    // Malicious code button
    document.getElementById('malicious-code-btn').addEventListener('click', () => {
      this.tryMaliciousCode();
    });

    // Execute code button (whatever is in textarea)
    document.getElementById('execute-btn').addEventListener('click', () => {
      const code = document.getElementById('code-input').value;
      this.executeCode(code);
    });

    // Sign transaction button
    document.getElementById('sign-btn').addEventListener('click', () => {
      this.signTransaction();
    });
  }

  async initialize() {
    const statusEl = document.getElementById('init-status');
    const btnEl = document.getElementById('init-btn');

    try {
      btnEl.disabled = true;
      statusEl.className = 'status pending';
      statusEl.innerHTML = '<div class="spinner"></div><div>Initializing enclave...</div>';

      console.log('🚀 [Demo] Starting enclave initialization...');
      console.log('🚀 [Demo] Host origin:', window.location.origin);
      console.log('🚀 [Demo] Expected enclave origin: http://localhost:3010');

      // Create enclave with iframe backend (default - CSP-compatible)
      // The iframe will be loaded from http://localhost:3010
      console.log('🚀 [Demo] Creating enclave instance...');
      this.enclave = await createEnclave();
      console.log('✅ [Demo] Enclave instance created:', this.enclave);

      console.log('🚀 [Demo] Calling enclave.initialize()...');
      await this.enclave.initialize();
      console.log('✅ [Demo] Enclave initialized successfully!');

      statusEl.className = 'status success';
      statusEl.innerHTML = '<div>✓ Enclave initialized successfully!</div>';

      // Enable other buttons
      document.getElementById('fibonacci-btn').disabled = false;
      document.getElementById('malicious-code-btn').disabled = false;
      document.getElementById('execute-btn').disabled = false;
      document.getElementById('sign-btn').disabled = false;

      console.log('Enclave initialized:', this.enclave);
    } catch (error) {
      console.error('Initialization error:', error);
      statusEl.className = 'status error';

      let errorMessage = error.message;

      // Check if error is caused by browser extension
      if (error.stack && error.stack.includes('contentScripts.bundle.js')) {
        errorMessage = 'Browser extension is interfering with WebAssembly. Please try: <br>' +
          '1. Disable browser extensions (especially ad blockers)<br>' +
          '2. Use an incognito/private window<br>' +
          '3. Try a different browser';
      }

      statusEl.innerHTML = `<div>✗ Error: ${errorMessage}</div>`;
      btnEl.disabled = false;
    }
  }

  async executeCode(code, options = {}) {
    const resultEl = document.getElementById('execute-result');

    try {
      resultEl.innerHTML = '<div class="status pending"><div class="spinner"></div><div>Executing code...</div></div>';

      // Read the zero memory toggle state
      const shouldZeroMemory = document.getElementById('zero-memory-toggle').checked;
      console.log('🔍 [Demo] Zero Memory toggle state:', shouldZeroMemory);

      const { result, metrics, totalDurationMs } = await this.enclave.execute(code, {
        message: 'Hello from host!',
        timestamp: Date.now(),
        zeroMemory: shouldZeroMemory
      });

      console.log('🔍 [Demo] Received metrics.memoryZeroed:', metrics.memoryZeroed);

      // Update metrics
      this.updateMetrics(metrics);

      // Display result with color-coded memory status
      const memoryStatus = metrics.memoryZeroed ?
        '<span style="color: #28a745;">true ✓</span>' :
        '<span style="color: #dc3545;">false ✗</span>';

      resultEl.innerHTML = `
        <div class="status success">
          <div>✓ Execution successful!</div>
        </div>
        <div class="code-block">Result: ${JSON.stringify(result, null, 2)}

Total Duration: ${totalDurationMs.toFixed(2)}ms
Key Exposure: ${metrics.keyExposureMs.toFixed(2)}ms
Memory Zeroed: ${memoryStatus}</div>
      `;
    } catch (error) {
      console.error('Execution error:', error);
      resultEl.innerHTML = `
        <div class="status error">
          <div>✗ Error: ${error.message}</div>
        </div>
      `;
    }
  }

  async tryMaliciousCode() {
    const maliciousCode = `
// Attempt to access host environment (will fail)
try {
  // Try to access global objects
  if (typeof window !== 'undefined') {
    return 'BREACH: Accessed window!';
  }
  if (typeof document !== 'undefined') {
    return 'BREACH: Accessed document!';
  }
  if (typeof fetch !== 'undefined') {
    return 'BREACH: Accessed fetch!';
  }
  if (typeof XMLHttpRequest !== 'undefined') {
    return 'BREACH: Accessed XMLHttpRequest!';
  }

  // Try to infinite loop (should be caught by timeout)
  // while(true) {}

  return 'SAFE: No host objects accessible!';
} catch (e) {
  return 'SAFE: Exception caught - ' + e.message;
}
`;

    // Set the textarea content, then execute
    document.getElementById('code-input').value = maliciousCode;
    await this.executeCode(maliciousCode);
  }

  async tryFibonacciCode() {
    const fibonacciCode = `// Example: Calculate Fibonacci
function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

return fibonacci(10)`;

    // Set the textarea content, then execute
    document.getElementById('code-input').value = fibonacciCode;
    await this.executeCode(fibonacciCode);
  }

  async signTransaction() {
    const resultEl = document.getElementById('sign-result');

    try {
      resultEl.innerHTML = '<div class="status pending"><div class="spinner"></div><div>Signing transaction...</div></div>';

      // Simulate an encrypted private key (in real app, this would come from user's storage)
      const mockEncryptedKey = new Uint8Array(64);
      crypto.getRandomValues(mockEncryptedKey);

      // Mock NEAR transaction (all required fields)
      const transaction = {
        signerId: 'alice.near',
        publicKey: 'ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847', // Mock public key
        receiverId: 'bob.near',
        nonce: String(Date.now()), // NEAR expects string
        blockHash: '4kxfS5Bz9wEhzbMbWbWjmPUBmJVsFcFjJVJkZhFZhHVC', // Mock block hash (32 bytes base58)
        actions: [{
          type: 'Transfer',
          deposit: '1000000000000000000000000' // 1 NEAR (field name is 'deposit' not 'amount')
        }]
      };

      const { signature, metrics, totalDurationMs } = await this.enclave.signTransaction(
        mockEncryptedKey,
        transaction
      );

      // Update metrics
      this.updateMetrics(metrics);

      // Display result
      resultEl.innerHTML = `
        <div class="status success">
          <div>✓ Transaction signed successfully!</div>
        </div>
        <div class="code-block">Signature Type: ${signature.type}
Signature Data: [${signature.data.slice(0, 8).join(', ')}...]

Total Duration: ${totalDurationMs.toFixed(2)}ms
Key Exposure: ${metrics.keyExposureMs.toFixed(2)}ms (Ephemeral!)
Memory Zeroed: ${metrics.memoryZeroed}

Transaction: ${JSON.stringify(transaction, null, 2)}</div>
      `;
    } catch (error) {
      console.error('Signing error:', error);
      resultEl.innerHTML = `
        <div class="status error">
          <div>✗ Error: ${error.message}</div>
        </div>
      `;
    }
  }

  updateMetrics(executionMetrics) {
    this.metrics.operations++;
    this.metrics.maxExposure = Math.max(
      this.metrics.maxExposure,
      executionMetrics.keyExposureMs
    );

    const enclaveMetrics = this.enclave.getMetrics();

    document.getElementById('metric-operations').textContent = this.metrics.operations;
    document.getElementById('metric-avg-exposure').textContent =
      `${enclaveMetrics.averageKeyExposureMs.toFixed(2)}ms`;
    document.getElementById('metric-max-exposure').textContent =
      `${this.metrics.maxExposure.toFixed(2)}ms`;
  }
}

// Initialize demo when page loads
const demo = new Demo();

// Expose for debugging
window.demo = demo;

console.log('Demo ready! Click "Initialize Enclave" to begin.');
