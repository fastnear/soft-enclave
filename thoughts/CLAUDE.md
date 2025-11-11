# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This is a research and documentation repository focused on analyzing WebAssembly memory isolation and security properties, particularly concerning QuickJS compiled to Wasm and whether it can serve as a "secure enclave" against the embedding page.

## Key Research Findings

The primary research document (01.txt) establishes:

1. **Memory Safety**: QuickJS-Wasm is memory-safe and isolated from the rest of the process (sandboxed by Wasm)
2. **Memory Confidentiality**: QuickJS-Wasm does NOT provide memory confidentiality from the embedding page by default
   - The host JavaScript can access the WebAssembly.Memory handle (via exports or imports)
   - With Emscripten defaults, memory is exported to JS
   - The quickjs-emscripten library exposes `mod.getWasmMemory()` API
3. **Security Model**: WebAssembly sandboxes modules to protect the host from modules, NOT to protect modules from the host

## Architecture Context

The research references a multi-layer architecture:
- L3: QuickJS layer
- L4: "Frozen Realm" that decrypts content

The analysis concludes that if L4 runs in the same origin as the host page, memory confidentiality does not follow from Wasm isolation alone. The recommendation is to shift L3/L4 into a cross-origin worker boundary with encrypted host↔guest payloads.

## Key Technical Concepts

- **WebAssembly.Memory**: The linear memory API that exposes heap as ArrayBuffer to JavaScript
- **Emscripten Memory Modes**: Default exports memory; `-sIMPORTED_MEMORY=1` changes who creates Memory but doesn't add confidentiality
- **Cross-Origin Isolation**: Suggested mitigation using cross-origin workers/iframes with postMessage and encrypted payloads
