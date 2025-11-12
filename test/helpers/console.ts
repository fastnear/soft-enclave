import { vi } from 'vitest';

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Mute expected console.error patterns while preserving unexpected errors
 *
 * @param patterns - Array of RegExp or strings to match against console.error messages
 * @returns Cleanup function to restore original console.error
 */
export function muteConsoleErrors(patterns: (RegExp | string)[]) {
  const orig = console.error;
  const matchers = patterns.map(p => p instanceof RegExp ? p : new RegExp(escapeRe(p), 'i'));
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: any[]) => {
    const msg = args.map(String).join(' ');
    if (matchers.some(rx => rx.test(msg))) return; // swallow expected
    (orig as any)(...args);                         // pass through the rest
  });
  return () => spy.mockRestore();
}

/**
 * Mute expected console.warn patterns while preserving unexpected warnings
 *
 * @param patterns - Array of RegExp or strings to match against console.warn messages
 * @returns Cleanup function to restore original console.warn
 */
export function muteConsoleWarns(patterns: (RegExp | string)[]) {
  const orig = console.warn;
  const matchers = patterns.map(p => p instanceof RegExp ? p : new RegExp(escapeRe(p), 'i'));
  const spy = vi.spyOn(console, 'warn').mockImplementation((...args: any[]) => {
    const msg = args.map(String).join(' ');
    if (matchers.some(rx => rx.test(msg))) return; // swallow expected
    (orig as any)(...args);                         // pass through the rest
  });
  return () => spy.mockRestore();
}
