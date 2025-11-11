/**
 * Base58 Encoding/Decoding
 *
 * Used for NEAR account IDs and public key encoding.
 * Uses Bitcoin's base58 alphabet (no 0, O, I, l to avoid confusion).
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHABET_MAP = new Map(ALPHABET.split('').map((c, i) => [c, BigInt(i)]));
const BASE = BigInt(58);

/**
 * Encode a Uint8Array to base58 string
 */
export function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Count leading zeros
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) {
    zeros++;
  }

  // Convert bytes to big integer
  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  // Convert to base58
  const result: string[] = [];
  while (num > 0n) {
    const remainder = num % BASE;
    num = num / BASE;
    result.unshift(ALPHABET[Number(remainder)]);
  }

  // Add leading 1s for leading zeros
  return '1'.repeat(zeros) + result.join('');
}

/**
 * Decode a base58 string to Uint8Array
 */
export function decodeBase58(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Count leading 1s (represent zero bytes)
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') {
    zeros++;
  }

  // Convert base58 to big integer
  let num = 0n;
  for (const char of str) {
    const digit = ALPHABET_MAP.get(char);
    if (digit === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    num = num * BASE + digit;
  }

  // Convert big integer to bytes
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  // Add leading zero bytes
  return new Uint8Array([...Array(zeros).fill(0), ...bytes]);
}
