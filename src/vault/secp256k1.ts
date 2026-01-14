/**
 * Certen Key Vault - ECDSA secp256k1 Key Operations
 *
 * Uses @noble/secp256k1 for Ethereum-compatible key generation and signing.
 */

import * as secp256k1 from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { toHex, fromHex } from './crypto';

// Configure HMAC for @noble/secp256k1 v2.x (required for signing)
secp256k1.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp256k1.etc.concatBytes(...m));

// =============================================================================
// Types
// =============================================================================

export interface Secp256k1KeyPair {
  publicKey: Uint8Array;    // 65 bytes (uncompressed) or 33 bytes (compressed)
  privateKey: Uint8Array;   // 32 bytes
}

export interface EthereumSignature {
  r: Uint8Array;            // 32 bytes
  s: Uint8Array;            // 32 bytes
  v: number;                // Recovery ID (27 or 28)
}

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generates a new random secp256k1 keypair.
 *
 * @param compressed - If true, return 33-byte compressed public key (default: false for 65-byte)
 * @returns secp256k1 keypair
 */
export function generateSecp256k1Key(compressed: boolean = false): Secp256k1KeyPair {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, compressed);
  return { publicKey, privateKey };
}

/**
 * Creates a secp256k1 keypair from a 32-byte private key.
 *
 * @param privateKey - 32-byte private key
 * @param compressed - If true, return 33-byte compressed public key
 * @returns secp256k1 keypair
 */
export function secp256k1FromPrivateKey(
  privateKey: Uint8Array,
  compressed: boolean = false
): Secp256k1KeyPair {
  if (privateKey.length !== 32) {
    throw new Error('secp256k1 private key must be 32 bytes');
  }
  const publicKey = secp256k1.getPublicKey(privateKey, compressed);
  return { publicKey, privateKey };
}

/**
 * Creates a secp256k1 keypair from a hex-encoded private key.
 *
 * @param privateKeyHex - Hex-encoded 32-byte private key (with or without 0x prefix)
 * @param compressed - If true, return compressed public key
 * @returns secp256k1 keypair
 */
export function secp256k1FromPrivateKeyHex(
  privateKeyHex: string,
  compressed: boolean = false
): Secp256k1KeyPair {
  const privateKey = fromHex(privateKeyHex);
  return secp256k1FromPrivateKey(privateKey, compressed);
}

// =============================================================================
// Signing
// =============================================================================

/**
 * Signs a message hash with a secp256k1 private key.
 * Returns a 65-byte signature in the format: r (32) + s (32) + v (1)
 *
 * @param messageHash - 32-byte message hash
 * @param privateKey - 32-byte private key
 * @returns 65-byte signature with recovery ID
 */
export async function signSecp256k1(
  messageHash: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  const signature = await secp256k1.signAsync(messageHash, privateKey, {
    lowS: true  // Enforce low-S for EIP-2
  });

  // Build 65-byte signature: r (32) + s (32) + v (1)
  const sig = new Uint8Array(65);

  // r is 32 bytes
  const rBytes = signature.r.toString(16).padStart(64, '0');
  const rArray = fromHex(rBytes);
  sig.set(rArray, 0);

  // s is 32 bytes
  const sBytes = signature.s.toString(16).padStart(64, '0');
  const sArray = fromHex(sBytes);
  sig.set(sArray, 32);

  // v is recovery ID + 27 (Ethereum format)
  sig[64] = signature.recovery + 27;

  return sig;
}

/**
 * Signs a hex-encoded hash with a secp256k1 private key.
 *
 * @param hashHex - Hex-encoded 32-byte hash (with or without 0x prefix)
 * @param privateKeyHex - Hex-encoded 32-byte private key
 * @returns Hex-encoded 65-byte signature
 */
export async function signSecp256k1Hex(
  hashHex: string,
  privateKeyHex: string
): Promise<string> {
  const hash = fromHex(hashHex);
  const privateKey = fromHex(privateKeyHex);
  const signature = await signSecp256k1(hash, privateKey);
  return '0x' + toHex(signature);
}

// =============================================================================
// Verification
// =============================================================================

/**
 * Verifies a secp256k1 signature.
 *
 * @param messageHash - 32-byte message hash
 * @param signature - 64-byte signature (r + s, without v)
 * @param publicKey - Public key (33 or 65 bytes)
 * @returns true if signature is valid
 */
export function verifySecp256k1(
  messageHash: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  return secp256k1.verify(signature.slice(0, 64), messageHash, publicKey);
}

// =============================================================================
// Ethereum-Specific Functions
// =============================================================================

/**
 * Computes the Ethereum address from a public key.
 *
 * @param publicKey - 65-byte uncompressed public key (or 64 bytes without prefix)
 * @returns Ethereum address with 0x prefix
 */
export function getEthAddress(publicKey: Uint8Array): string {
  // Remove 0x04 prefix if present (uncompressed public key marker)
  const key = publicKey.length === 65 ? publicKey.slice(1) : publicKey;

  if (key.length !== 64) {
    throw new Error('Public key must be 64 bytes (uncompressed without prefix) or 65 bytes (with 0x04 prefix)');
  }

  // Keccak-256 hash of the public key
  const hash = keccak256(key);

  // Take last 20 bytes as address
  const addressBytes = hash.slice(-20);
  return '0x' + toHex(addressBytes);
}

/**
 * Keccak-256 hash function (Ethereum's SHA-3 variant).
 * Uses @noble/hashes for proper Keccak-256.
 */
function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

/**
 * Computes the EIP-191 signed message hash.
 * Prepends "\x19Ethereum Signed Message:\n{length}" to the message.
 *
 * @param message - Original message string or bytes
 * @returns 32-byte hash ready for signing
 */
export function hashEthSignedMessage(message: string | Uint8Array): Uint8Array {
  const encoder = new TextEncoder();
  const messageBytes = typeof message === 'string' ? encoder.encode(message) : message;

  const prefix = encoder.encode(`\x19Ethereum Signed Message:\n${messageBytes.length}`);

  const combined = new Uint8Array(prefix.length + messageBytes.length);
  combined.set(prefix, 0);
  combined.set(messageBytes, prefix.length);

  return keccak256(combined);
}

/**
 * Signs an Ethereum personal message (EIP-191).
 *
 * @param message - Message to sign
 * @param privateKey - 32-byte private key
 * @returns 65-byte signature with recovery ID
 */
export async function signEthPersonalMessage(
  message: string | Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  const hash = hashEthSignedMessage(message);
  return signSecp256k1(hash, privateKey);
}

// =============================================================================
// Utility Exports
// =============================================================================

export { toHex, fromHex };
