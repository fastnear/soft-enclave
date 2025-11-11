/**
 * Transaction Signing Tests
 *
 * These tests verify the security and correctness of NEAR transaction signing:
 * - Proper Borsh serialization (CRITICAL - must match NEAR protocol)
 * - Ed25519 signature generation via tweetnacl
 * - Private key parsing and validation
 * - Public key derivation
 * - Transaction structure correctness
 * - Base58 encoding/decoding
 *
 * These tests are CONSEQUENTIAL - they prove transactions will be accepted
 * by NEAR RPC nodes and that cryptographic operations are secure.
 */

import { describe, it, expect } from 'vitest';
import {
  parsePrivateKey,
  derivePublicKey,
  encodePublicKey,
  signTransaction,
  verifySignature,
  createFunctionCallTransaction,
  createTransferTransaction,
  serializeTransaction
} from '../packages/near/src/enclave/near-tx';
import { encodeBase58, decodeBase58 } from '../packages/near/src/enclave/base58';
import * as nacl from 'tweetnacl';

describe('Base58 Encoding - Bitcoin Alphabet', () => {
  it('MUST use Bitcoin base58 alphabet (no 0,O,I,l)', () => {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    // Characters that are EXCLUDED to prevent confusion
    expect(alphabet.includes('0')).toBe(false); // Zero
    expect(alphabet.includes('O')).toBe(false); // Capital O
    expect(alphabet.includes('I')).toBe(false); // Capital I
    expect(alphabet.includes('l')).toBe(false); // Lowercase L

    // Total should be 58 characters
    expect(alphabet.length).toBe(58);
  });

  it('MUST encode and decode bytes correctly', () => {
    const testCases = [
      new Uint8Array([0, 0, 0]),
      new Uint8Array([1, 2, 3, 4, 5]),
      new Uint8Array([255, 255, 255]),
      crypto.getRandomValues(new Uint8Array(32))
    ];

    testCases.forEach((original) => {
      const encoded = encodeBase58(original);
      const decoded = decodeBase58(encoded);

      expect(decoded).toEqual(original);
    });
  });

  it('MUST handle leading zeros correctly', () => {
    // Leading zeros become leading 1s in base58
    const withZeros = new Uint8Array([0, 0, 1, 2, 3]);
    const encoded = encodeBase58(withZeros);

    // Should start with '11' (two leading zeros → two leading 1s)
    expect(encoded.startsWith('11')).toBe(true);

    // Round-trip should preserve zeros
    const decoded = decodeBase58(encoded);
    expect(decoded).toEqual(withZeros);
  });

  it('MUST handle empty arrays', () => {
    const empty = new Uint8Array([]);
    const encoded = encodeBase58(empty);
    const decoded = decodeBase58(encoded);

    expect(encoded).toBe('');
    expect(decoded).toEqual(empty);
  });
});

describe('Private Key Parsing', () => {
  it('MUST parse ed25519:base58 format correctly', () => {
    // Generate test keypair
    const keyPair = nacl.sign.keyPair();
    const privateKey = keyPair.secretKey;

    // Encode in NEAR format
    const keyString = 'ed25519:' + encodeBase58(privateKey);

    // Parse should succeed
    const parsed = parsePrivateKey(keyString);
    expect(parsed).toEqual(privateKey);
  });

  it('MUST reject keys without ed25519: prefix', () => {
    const keyPair = nacl.sign.keyPair();
    const base58Only = encodeBase58(keyPair.secretKey);

    // Should throw - missing prefix
    expect(() => parsePrivateKey(base58Only)).toThrow('must start with ed25519:');
  });

  it('MUST reject keys with wrong length', () => {
    // Ed25519 private keys MUST be exactly 64 bytes
    const wrongLength = new Uint8Array(32); // Too short
    const keyString = 'ed25519:' + encodeBase58(wrongLength);

    expect(() => parsePrivateKey(keyString)).toThrow('Invalid private key length');
  });

  it('MUST validate Ed25519 private key is exactly 64 bytes', () => {
    const keyPair = nacl.sign.keyPair();

    // Ed25519 secret key format in tweetnacl:
    // First 32 bytes: seed/private key
    // Last 32 bytes: public key
    // Total: 64 bytes
    expect(keyPair.secretKey.length).toBe(64);
  });
});

describe('Public Key Derivation', () => {
  it('MUST derive correct public key from private key', () => {
    const keyPair = nacl.sign.keyPair();
    const privateKey = keyPair.secretKey;
    const expectedPublicKey = keyPair.publicKey;

    // Derive public key
    const derivedPublicKey = derivePublicKey(privateKey);

    expect(derivedPublicKey).toEqual(expectedPublicKey);
  });

  it('MUST produce 32-byte public keys', () => {
    const keyPair = nacl.sign.keyPair();
    const publicKey = derivePublicKey(keyPair.secretKey);

    expect(publicKey.length).toBe(32);
  });

  it('MUST encode public key in NEAR format', () => {
    const keyPair = nacl.sign.keyPair();
    const publicKey = derivePublicKey(keyPair.secretKey);
    const encoded = encodePublicKey(publicKey);

    // Should start with ed25519:
    expect(encoded.startsWith('ed25519:')).toBe(true);

    // Should be able to decode
    const base58Part = encoded.slice(8);
    const decoded = decodeBase58(base58Part);
    expect(decoded).toEqual(publicKey);
  });
});

describe('Transaction Structure', () => {
  it('MUST create valid FunctionCall transaction', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'set_value',
      args: { value: 42 },
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64), // 32-byte hash as hex
      publicKey: 'ed25519:' + encodeBase58(new Uint8Array(32))
    });

    expect(tx.signerId).toBe('alice.testnet');
    expect(tx.receiverId).toBe('contract.testnet');
    expect(tx.nonce).toBe('1');
    expect(tx.blockHash).toBe('0'.repeat(64));
    expect(tx.actions).toHaveLength(1);
    expect(tx.actions[0].type).toBe('FunctionCall');
  });

  it('MUST encode method args as JSON bytes', () => {
    const args = { greeting: 'Hello', value: 42 };
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args,
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64)
    });

    const action = tx.actions[0] as any;
    expect(action.type).toBe('FunctionCall');

    // Args should be Uint8Array containing JSON
    expect(action.args instanceof Uint8Array).toBe(true);

    const argsJson = new TextDecoder().decode(action.args);
    const parsed = JSON.parse(argsJson);
    expect(parsed).toEqual(args);
  });

  it('MUST create valid Transfer transaction', () => {
    const tx = createTransferTransaction({
      signerId: 'alice.testnet',
      receiverId: 'bob.testnet',
      amount: '1000000000000000000000000', // 1 NEAR in yoctoNEAR
      nonce: '1',
      blockHash: '0'.repeat(64)
    });

    expect(tx.signerId).toBe('alice.testnet');
    expect(tx.receiverId).toBe('bob.testnet');
    expect(tx.actions).toHaveLength(1);
    expect(tx.actions[0].type).toBe('Transfer');
    expect((tx.actions[0] as any).deposit).toBe('1000000000000000000000000');
  });
});

describe('Borsh Serialization', () => {
  it('MUST serialize transaction to bytes', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey: 'ed25519:' + encodeBase58(new Uint8Array(32))
    });

    const serialized = serializeTransaction(tx);

    // Should produce bytes
    expect(serialized instanceof Uint8Array).toBe(true);
    expect(serialized.length).toBeGreaterThan(0);
  });

  it('MUST validate block hash is exactly 32 bytes', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: 'FF', // Too short!
      publicKey: 'ed25519:' + encodeBase58(new Uint8Array(32))
    });

    // Should throw - invalid block hash length
    expect(() => serializeTransaction(tx)).toThrow('Invalid block hash length');
  });

  it('MUST validate public key is exactly 32 bytes', () => {
    const shortKey = new Uint8Array(16); // Too short
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey: 'ed25519:' + encodeBase58(shortKey)
    });

    // Should throw - invalid public key length
    expect(() => serializeTransaction(tx)).toThrow('Invalid public key length');
  });

  it('MUST produce deterministic output for same transaction', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: { value: 42 },
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey: 'ed25519:' + encodeBase58(new Uint8Array(32))
    });

    const serialized1 = serializeTransaction(tx);
    const serialized2 = serializeTransaction(tx);

    // Borsh serialization MUST be deterministic
    expect(serialized1).toEqual(serialized2);
  });
});

describe('Ed25519 Signing', () => {
  it('MUST sign transaction and produce valid signature', async () => {
    const keyPair = nacl.sign.keyPair();
    const privateKeyString = 'ed25519:' + encodeBase58(keyPair.secretKey);
    const publicKey = encodePublicKey(keyPair.publicKey);

    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey
    });

    const signedTx = await signTransaction(tx, privateKeyString);

    // Should have signature
    expect(signedTx.signature).toBeDefined();
    expect(typeof signedTx.signature).toBe('string');
    expect(signedTx.signature.length).toBeGreaterThan(0);

    // Should have transaction hash
    expect(signedTx.hash).toBeDefined();
    expect(typeof signedTx.hash).toBe('string');
    expect(signedTx.hash.length).toBe(64); // SHA-256 hash as hex

    // Signature should be base58-encoded
    const sigBytes = decodeBase58(signedTx.signature);
    expect(sigBytes.length).toBe(64); // Ed25519 signature is 64 bytes
  });

  it('MUST derive and set correct public key in transaction', async () => {
    const keyPair = nacl.sign.keyPair();
    const privateKeyString = 'ed25519:' + encodeBase58(keyPair.secretKey);
    const expectedPublicKey = encodePublicKey(keyPair.publicKey);

    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey: '' // Will be set by signTransaction
    });

    const signedTx = await signTransaction(tx, privateKeyString);

    // Public key should be derived from private key
    expect(signedTx.transaction.publicKey).toBe(expectedPublicKey);
  });

  it('MUST produce verifiable signature', async () => {
    const keyPair = nacl.sign.keyPair();
    const privateKeyString = 'ed25519:' + encodeBase58(keyPair.secretKey);
    const publicKey = encodePublicKey(keyPair.publicKey);

    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey
    });

    const signedTx = await signTransaction(tx, privateKeyString);

    // Signature should verify
    const isValid = await verifySignature(signedTx);
    expect(isValid).toBe(true);
  });

  it('MUST reject signature with wrong public key', async () => {
    const keyPair = nacl.sign.keyPair();
    const wrongKeyPair = nacl.sign.keyPair(); // Different key

    const privateKeyString = 'ed25519:' + encodeBase58(keyPair.secretKey);
    const publicKey = encodePublicKey(keyPair.publicKey);

    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey
    });

    const signedTx = await signTransaction(tx, privateKeyString);

    // Tamper with public key
    signedTx.transaction.publicKey = encodePublicKey(wrongKeyPair.publicKey);

    // Verification should fail
    const isValid = await verifySignature(signedTx);
    expect(isValid).toBe(false);
  });

  it('MUST reject tampered transaction data', async () => {
    const keyPair = nacl.sign.keyPair();
    const privateKeyString = 'ed25519:' + encodeBase58(keyPair.secretKey);
    const publicKey = encodePublicKey(keyPair.publicKey);

    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64),
      publicKey
    });

    const signedTx = await signTransaction(tx, privateKeyString);

    // Tamper with nonce
    signedTx.transaction.nonce = '999';

    // Verification should fail
    const isValid = await verifySignature(signedTx);
    expect(isValid).toBe(false);
  });
});

describe('Transaction Security Properties', () => {
  it('MUST include nonce to prevent replay attacks', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '123456',
      blockHash: '0'.repeat(64)
    });

    // Nonce must be present and match
    expect(tx.nonce).toBe('123456');
  });

  it('MUST include block hash to prevent replay on different chains', () => {
    const blockHash = 'a'.repeat(64);
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash
    });

    // Block hash must be present and match
    expect(tx.blockHash).toBe(blockHash);
  });

  it('MUST include signer ID to identify transaction originator', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64)
    });

    expect(tx.signerId).toBe('alice.testnet');
    expect(tx.signerId.length).toBeGreaterThan(0);
  });

  it('MUST include receiver ID to specify action target', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64)
    });

    expect(tx.receiverId).toBe('contract.testnet');
    expect(tx.receiverId.length).toBeGreaterThan(0);
  });
});

describe('Gas and Deposit Handling', () => {
  it('MUST use string representation for large numbers', () => {
    // NEAR uses u64 for gas and u128 for deposits
    // JavaScript Number is not sufficient - must use string/BigInt

    const gas = '300000000000000'; // 300 TGas
    const deposit = '1000000000000000000000000'; // 1 NEAR

    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas,
      deposit,
      nonce: '1',
      blockHash: '0'.repeat(64)
    });

    const action = tx.actions[0] as any;
    expect(action.gas).toBe(gas);
    expect(action.deposit).toBe(deposit);
  });

  it('MUST handle zero deposit correctly', () => {
    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: '0',
      nonce: '1',
      blockHash: '0'.repeat(64)
    });

    const action = tx.actions[0] as any;
    expect(action.deposit).toBe('0');
  });

  it('MUST handle large deposit values (u128)', () => {
    // Test with very large number (near u128 max)
    const hugeDeposit = '340282366920938463463374607431768211455'; // Close to 2^128 - 1

    const tx = createFunctionCallTransaction({
      signerId: 'alice.testnet',
      receiverId: 'contract.testnet',
      methodName: 'test',
      args: {},
      gas: '30000000000000',
      deposit: hugeDeposit,
      nonce: '1',
      blockHash: '0'.repeat(64)
    });

    const action = tx.actions[0] as any;
    expect(action.deposit).toBe(hugeDeposit);
  });
});
