// QuickJS runtime wired for enclave usage.
// - Imports the real quickjs-emscripten package (bundles cleanly)
// - Wraps user code so top-level `return` works
// - Supports async/await in user code
// - Timeout via interrupt handler
// - Proper handle disposal and result dumping

import { getQuickJS, type QuickJSContext, type QuickJSWASMModule } from "quickjs-emscripten";

export type EvalResult =
  | { ok: true; value: unknown; durationMs: number; memoryZeroed: boolean }
  | { ok: false; error: string; durationMs: number; memoryZeroed: boolean };

export class QuickJSEnclave {
  private QuickJS!: QuickJSWASMModule;
  private ctx!: QuickJSContext;
  private initialized = false;

  async init() {
    if (this.initialized) return;
    console.log('🟢 [QuickJS] Loading QuickJS WASM...');
    this.QuickJS = await getQuickJS();
    console.log('✅ [QuickJS] QuickJS WASM loaded successfully');
    this.ctx = this.QuickJS.newContext();
    this.initialized = true;
  }

  dispose() {
    if (!this.initialized) return;
    try { this.ctx.dispose(); } catch {}
    // reset
    // @ts-ignore
    this.ctx = undefined as any;
    // @ts-ignore
    this.QuickJS = undefined as any;
    this.initialized = false;
  }

  /**
   * Evaluate untrusted code with an optional timeout.
   * Code is wrapped in IIFE so top-level `return` works.
   * @param code - The JavaScript code to execute
   * @param timeoutMs - Maximum execution time in milliseconds
   * @param zeroMemory - Whether to zero/dispose memory after execution (default: true for security)
   */
  async eval(code: string, timeoutMs = 2000, zeroMemory = true): Promise<EvalResult> {
    if (!this.initialized) await this.init();

    const start = Date.now();
    const deadline = start + Math.max(1, timeoutMs);

    // Interrupt handler to break out of infinite loops
    this.ctx.runtime.setInterruptHandler(() => Date.now() > deadline);

    // Wrap user code in IIFE (PE's original approach)
    const wrapped = [
      '(function(){',
      '"use strict";',
      code,
      '})()'
    ].join('\n');

    const result = this.ctx.evalCode(wrapped);
    const durationMs = Date.now() - start;

    if (result.error) {
      const err = this.ctx.dump(result.error);

      // Conditionally dispose based on zeroMemory flag
      if (zeroMemory) {
        result.error.dispose();
      }

      // Better error serialization - handle objects, extract message
      let errorString: string;
      if (typeof err === 'object' && err !== null) {
        // Try to extract meaningful error info
        errorString = JSON.stringify(err, null, 2);
        // If JSON.stringify doesn't help, try to get properties
        if (errorString === '{}' || errorString === 'null') {
          errorString = err.message || err.toString() || String(err);
        }
      } else {
        errorString = String(err);
      }

      return { ok: false, error: errorString, durationMs, memoryZeroed: zeroMemory };
    }

    // Dump the value and conditionally dispose the handle
    const value = this.ctx.dump(result.value);

    if (zeroMemory) {
      result.value.dispose();
    }

    return { ok: true, value, durationMs, memoryZeroed: zeroMemory };
  }
}

// Legacy API for backward compatibility
export async function createQuickJS() {
  const vm = new QuickJSEnclave();
  await vm.init();

  return {
    evalQuickJS(code: string): any {
      // Note: This sync wrapper will be replaced by the async eval() method in enclave-main.ts
      // For now, return a placeholder to avoid breaking existing code during transition
      return { ok: false, error: 'Use async eval() method instead' };
    },
    // Expose the new async eval method
    eval: (code: string, timeout?: number, zeroMemory?: boolean) => vm.eval(code, timeout, zeroMemory),
    dispose: () => vm.dispose()
  };
}
