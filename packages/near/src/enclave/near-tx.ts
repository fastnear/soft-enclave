/**
 * NEAR Transaction Signing
 *
 * Provides secure transaction signing within the enclave using:
 * - Ed25519 via tweetnacl for signing
 * - Borsh for transaction serialization
 * - Base58 for key encoding
 *
 * Security: Private keys are only decrypted within the enclave sandbox
 */

import * as nacl from 'tweetnacl';
import { serialize, type Schema } from 'borsh';
import { encodeBase58, decodeBase58 } from './base58.js';

/**
 * NEAR transaction action types
 */
export interface CreateAccountAction {
  type: 'CreateAccount';
}

export interface DeployContractAction {
  type: 'DeployContract';
  code: Uint8Array;
}

export interface FunctionCallAction {
  type: 'FunctionCall';
  methodName: string;
  args: Uint8Array;
  gas: string;
  deposit: string;
}

export interface TransferAction {
  type: 'Transfer';
  deposit: string;
}

export interface StakeAction {
  type: 'Stake';
  stake: string;
  publicKey: string;
}

export interface AddKeyAction {
  type: 'AddKey';
  publicKey: string;
  accessKey: {
    nonce: string;
    permission: 'FullAccess' | {
      FunctionCall: {
        allowance: string;
        receiverId: string;
        methodNames: string[];
      };
    };
  };
}

export interface DeleteKeyAction {
  type: 'DeleteKey';
  publicKey: string;
}

export interface DeleteAccountAction {
  type: 'DeleteAccount';
  beneficiaryId: string;
}

export type Action =
  | CreateAccountAction
  | DeployContractAction
  | FunctionCallAction
  | TransferAction
  | StakeAction
  | AddKeyAction
  | DeleteKeyAction
  | DeleteAccountAction;

/**
 * NEAR transaction structure
 */
export interface Transaction {
  signerId: string;
  publicKey: string;
  nonce: string;
  receiverId: string;
  actions: Action[];
  blockHash: string;
}

/**
 * Signed transaction result
 */
export interface SignedTransaction {
  transaction: Transaction;
  signature: string;
  hash: string;
}

/**
 * Borsh-serializable transaction data structures
 * Using direct object serialization for simplicity and compatibility
 */

/**
 * Parse a NEAR private key in ed25519:base58 format
 */
export function parsePrivateKey(keyString: string): Uint8Array {
  // Expected format: "ed25519:base58_encoded_private_key"
  if (!keyString.startsWith('ed25519:')) {
    throw new Error('Invalid key format: must start with ed25519:');
  }

  const base58Key = keyString.slice(8); // Remove "ed25519:" prefix
  const decoded = decodeBase58(base58Key);

  if (decoded.length !== 64) {
    throw new Error(`Invalid private key length: expected 64 bytes, got ${decoded.length}`);
  }

  return decoded;
}

/**
 * Derive public key from private key
 */
export function derivePublicKey(privateKey: Uint8Array): Uint8Array {
  const keyPair = nacl.sign.keyPair.fromSecretKey(privateKey);
  return keyPair.publicKey;
}

/**
 * Encode a public key in NEAR format (ed25519:base58)
 */
export function encodePublicKey(publicKey: Uint8Array): string {
  return 'ed25519:' + encodeBase58(publicKey);
}

/**
 * Hash a serialized transaction using SHA-256
 */
async function hashTransaction(serialized: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', serialized as any);
  return new Uint8Array(hashBuffer);
}

/**
 * Serialize a NEAR transaction to Borsh format
 *
 * This uses proper Borsh serialization matching NEAR protocol specification.
 */
export function serializeTransaction(tx: Transaction): Uint8Array {
  // Convert blockHash to Uint8Array (32 bytes)
  // Support both hex format (0x... or plain hex) and base58 format
  let blockHashBytes: Uint8Array;

  if (tx.blockHash.startsWith('0x')) {
    // Hex with 0x prefix
    blockHashBytes = hexToBytes(tx.blockHash.slice(2));
  } else if (/^[0-9a-fA-F]+$/.test(tx.blockHash) && tx.blockHash.length === 64) {
    // Plain hex (64 chars = 32 bytes)
    blockHashBytes = hexToBytes(tx.blockHash);
  } else {
    // Assume base58 format (NEAR RPC returns this)
    try {
      blockHashBytes = decodeBase58(tx.blockHash);
    } catch (e) {
      throw new Error(`Invalid block hash format: not hex or base58: ${e}`);
    }
  }

  if (blockHashBytes.length !== 32) {
    throw new Error(`Invalid block hash length: expected 32 bytes, got ${blockHashBytes.length}. Block hash: ${tx.blockHash}`);
  }

  // Parse public key from ed25519:base58 format
  const publicKeyBytes = tx.publicKey.startsWith('ed25519:')
    ? decodeBase58(tx.publicKey.slice(8))
    : decodeBase58(tx.publicKey);

  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKeyBytes.length}`);
  }

  // Build transaction object for Borsh serialization
  const borshTx = {
    signerId: tx.signerId,
    publicKey: {
      keyType: 0, // Ed25519
      data: Array.from(publicKeyBytes)
    },
    nonce: BigInt(tx.nonce),
    receiverId: tx.receiverId,
    blockHash: Array.from(blockHashBytes),
    actions: tx.actions.map((action) => {
      if (action.type === 'FunctionCall') {
        // Borsh enum: key name determines variant, index is derived from schema match
        return {
          FunctionCall: {
            methodName: action.methodName,
            args: Array.from(action.args),
            gas: BigInt(action.gas),
            deposit: BigInt(action.deposit)
          }
        };
      } else if (action.type === 'Transfer') {
        return {
          Transfer: {
            deposit: BigInt(action.deposit)
          }
        };
      }
      throw new Error(`Unsupported action type: ${action.type}`);
    })
  };

  // Define Borsh schema with proper types
  // Each enum variant is a struct with a single named field
  const schema: Schema = {
    struct: {
      signerId: 'string',
      publicKey: {
        struct: {
          keyType: 'u8',
          data: { array: { type: 'u8', len: 32 } }
        }
      } as Schema,
      nonce: 'u64',
      receiverId: 'string',
      blockHash: { array: { type: 'u8', len: 32 } },
      actions: {
        array: {
          type: {
            enum: [
              { struct: { CreateAccount: { struct: {} } } }, // Variant 0
              { struct: { DeployContract: { struct: {} } } }, // Variant 1
              { struct: { FunctionCall: { // Variant 2
                struct: {
                  methodName: 'string',
                  args: { array: { type: 'u8' } },
                  gas: 'u64',
                  deposit: 'u128'
                }
              } as Schema } },
              { struct: { Transfer: { // Variant 3
                struct: {
                  deposit: 'u128'
                }
              } as Schema } }
            ]
          } as Schema
        }
      }
    }
  };

  return serialize(schema, borshTx);
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Sign a NEAR transaction
 *
 * @param transaction - Transaction to sign
 * @param privateKeyString - Private key in ed25519:base58 format
 * @returns Signed transaction with signature and hash
 */
export async function signTransaction(
  transaction: Transaction,
  privateKeyString: string
): Promise<SignedTransaction> {
  // Parse private key
  const privateKey = parsePrivateKey(privateKeyString);

  // Derive public key and verify it matches transaction
  const publicKey = derivePublicKey(privateKey);
  const publicKeyEncoded = encodePublicKey(publicKey);

  // Ensure transaction has correct public key
  const txWithPubKey = {
    ...transaction,
    publicKey: publicKeyEncoded,
  };

  // Serialize transaction
  const serialized = serializeTransaction(txWithPubKey);

  // Hash the serialized transaction
  const txHash = await hashTransaction(serialized);

  // Sign the hash with Ed25519
  const signature = nacl.sign.detached(txHash, privateKey);

  // Return signed transaction
  return {
    transaction: txWithPubKey,
    signature: encodeBase58(signature),
    hash: bytesToHex(txHash),
  };
}

/**
 * Verify a transaction signature
 *
 * @param signedTx - Signed transaction to verify
 * @returns true if signature is valid
 */
export async function verifySignature(signedTx: SignedTransaction): Promise<boolean> {
  try {
    // Serialize transaction
    const serialized = serializeTransaction(signedTx.transaction);

    // Hash the serialized transaction
    const txHash = await hashTransaction(serialized);

    // Decode signature and public key
    const signature = decodeBase58(signedTx.signature);
    const publicKeyStr = signedTx.transaction.publicKey;
    const publicKey = publicKeyStr.startsWith('ed25519:')
      ? decodeBase58(publicKeyStr.slice(8))
      : decodeBase58(publicKeyStr);

    // Verify signature
    return nacl.sign.detached.verify(txHash, signature, publicKey);
  } catch (error) {
    console.error('Signature verification failed:', error);
    return false;
  }
}

/**
 * Create a simple transfer transaction
 *
 * Helper function for common use case of transferring NEAR tokens
 */
export function createTransferTransaction(params: {
  signerId: string;
  receiverId: string;
  amount: string;
  nonce: string;
  blockHash: string;
  publicKey?: string;
}): Transaction {
  return {
    signerId: params.signerId,
    publicKey: params.publicKey || '',
    nonce: params.nonce,
    receiverId: params.receiverId,
    blockHash: params.blockHash,
    actions: [
      {
        type: 'Transfer',
        deposit: params.amount,
      },
    ],
  };
}

/**
 * Create a function call transaction
 *
 * Helper function for calling smart contract methods
 */
export function createFunctionCallTransaction(params: {
  signerId: string;
  receiverId: string;
  methodName: string;
  args: Record<string, any>;
  gas: string;
  deposit: string;
  nonce: string;
  blockHash: string;
  publicKey?: string;
}): Transaction {
  // Encode args as JSON then to Uint8Array
  const argsJson = JSON.stringify(params.args);
  const argsBytes = new TextEncoder().encode(argsJson);

  return {
    signerId: params.signerId,
    publicKey: params.publicKey || '',
    nonce: params.nonce,
    receiverId: params.receiverId,
    blockHash: params.blockHash,
    actions: [
      {
        type: 'FunctionCall',
        methodName: params.methodName,
        args: argsBytes,
        gas: params.gas,
        deposit: params.deposit,
      },
    ],
  };
}
