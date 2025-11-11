declare module 'quickjs-emscripten' {
  export function newQuickJSWASMModule(): Promise<QuickJSWASM>;
  export function newQuickJSAsyncWASMModule(): Promise<QuickJSWASM>;

  export interface QuickJSWASM {
    newContext(): QuickJSContext;
    newRuntime(): QuickJSRuntime;
  }

  export interface QuickJSRuntime {
    newContext(): QuickJSContext;
    dispose(): void;
  }

  export interface QuickJSContext {
    evalCode(code: string, filename?: string): QuickJSHandle;
    unwrapResult(result: QuickJSHandle): QuickJSHandle;
    getString(handle: QuickJSHandle): string;
    getNumber(handle: QuickJSHandle): number;
    typeof(handle: QuickJSHandle): string;
    newObject(): QuickJSHandle;
    newArray(): QuickJSHandle;
    newString(value: string): QuickJSHandle;
    newNumber(value: number): QuickJSHandle;
    newFunction(name: string, fn: (...args: any[]) => any): QuickJSHandle;
    setProp(target: QuickJSHandle, key: string, value: QuickJSHandle): void;
    getProp(target: QuickJSHandle, key: string): QuickJSHandle;
    dump(handle: QuickJSHandle): any;
    dispose(): void;
  }

  export type QuickJSHandle = any;
}
