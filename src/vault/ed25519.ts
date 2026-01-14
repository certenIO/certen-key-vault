/**
 * Certen Key Vault - ED25519 Key Operations
 *
 * Uses tweetnacl for ED25519 key generation and signing.
 * Compatible with the Accumulate TypeScript SDK.
 */

import * as nacl from 'tweetnacl';
import { toHex, fromHex } from './crypto';

// =============================================================================
// Types
// =============================================================================

export interface ED25519KeyPair {
  publicKey: Uint8Array;    // 32 bytes
  privateKey: Uint8Array;   // 64 bytes (32-byte seed + 32-byte public key)
}

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generates a new random ED25519 keypair.
 *
 * @returns ED25519 keypair with 32-byte public key and 64-byte private key
 */
export function generateED25519Key(): ED25519KeyPair {
  const keyPair = nacl.sign.keyPair();
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.secretKey
  };
}

/**
 * Creates an ED25519 keypair from a 32-byte seed.
 *
 * @param seed - 32-byte seed (can be derived from mnemonic)
 * @returns ED25519 keypair
 * @throws Error if seed is not 32 bytes
 */
export function ed25519FromSeed(seed: Uint8Array): ED25519KeyPair {
  if (seed.length !== 32) {
    throw new Error('ED25519 seed must be 32 bytes');
  }
  const keyPair = nacl.sign.keyPair.fromSeed(seed);
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.secretKey
  };
}

/**
 * Creates an ED25519 keypair from a hex-encoded private key.
 * Supports both 32-byte seeds and 64-byte full private keys.
 *
 * @param privateKeyHex - Hex-encoded private key (64 or 128 characters)
 * @returns ED25519 keypair
 */
export function ed25519FromPrivateKey(privateKeyHex: string): ED25519KeyPair {
  const privateKeyBytes = fromHex(privateKeyHex);

  if (privateKeyBytes.length === 32) {
    // 32-byte seed
    return ed25519FromSeed(privateKeyBytes);
  } else if (privateKeyBytes.length === 64) {
    // Full 64-byte private key (seed + public key)
    const publicKey = privateKeyBytes.slice(32);
    return {
      publicKey,
      privateKey: privateKeyBytes
    };
  } else {
    throw new Error('ED25519 private key must be 32 or 64 bytes');
  }
}

// =============================================================================
// Signing
// =============================================================================

/**
 * Signs a message with an ED25519 private key.
 *
 * @param message - Message bytes to sign (usually a hash)
 * @param privateKey - 64-byte ED25519 private key
 * @returns 64-byte signature
 */
export function signED25519(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, privateKey);
}

/**
 * Signs a hex-encoded hash with an ED25519 private key.
 *
 * @param hashHex - Hex-encoded hash to sign
 * @param privateKeyHex - Hex-encoded 64-byte private key
 * @returns Hex-encoded 64-byte signature
 */
export function signED25519Hex(hashHex: string, privateKeyHex: string): string {
  const hash = fromHex(hashHex);
  const privateKey = fromHex(privateKeyHex);
  const signature = signED25519(hash, privateKey);
  return toHex(signature);
}

// =============================================================================
// Verification
// =============================================================================

/**
 * Verifies an ED25519 signature.
 *
 * @param message - Original message bytes
 * @param signature - 64-byte signature
 * @param publicKey - 32-byte public key
 * @returns true if signature is valid
 */
export function verifyED25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  return nacl.sign.detached.verify(message, signature, publicKey);
}

// =============================================================================
// Accumulate-Specific Functions
// =============================================================================

/**
 * SHA-256 hash implementation for Accumulate lite account URL generation.
 * Uses Web Crypto API.
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer);
  return new Uint8Array(hashBuffer);
}

/**
 * Generates the Accumulate Lite Account URL from an ED25519 public key.
 *
 * The lite account URL is derived as:
 * 1. Hash the public key with SHA-256
 * 2. Take the first 20 bytes as the key hash
 * 3. Convert to hex string
 * 4. Hash the hex string with SHA-256
 * 5. Take the last 4 bytes as checksum
 * 6. Concatenate: acc://{keyHash}{checksum}
 *
 * @param publicKey - 32-byte ED25519 public key
 * @returns Lite account URL (e.g., "acc://105251bb367baa372c748930531ae63d6e143c9aa4470eff")
 */
export async function generateLiteAccountUrl(publicKey: Uint8Array): Promise<string> {
  // Step 1: Hash the public key
  const publicKeyHash = await sha256(publicKey);

  // Step 2: Take first 20 bytes as key hash
  const keyBytes = publicKeyHash.slice(0, 20);
  const keyHex = toHex(keyBytes);

  // Step 3: Hash the hex string for checksum
  const encoder = new TextEncoder();
  const checksumSource = await sha256(encoder.encode(keyHex));

  // Step 4: Take last 4 bytes as checksum
  const checksumBytes = checksumSource.slice(28); // Last 4 bytes of 32
  const checksumHex = toHex(checksumBytes);

  // Step 5: Concatenate
  return `acc://${keyHex}${checksumHex}`;
}

/**
 * Generates the public key hash used for Accumulate key identification.
 *
 * @param publicKey - 32-byte ED25519 public key
 * @returns Hex-encoded SHA-256 hash of the public key
 */
export async function getPublicKeyHash(publicKey: Uint8Array): Promise<string> {
  const hash = await sha256(publicKey);
  return toHex(hash);
}

// =============================================================================
// Utility Exports
// =============================================================================

export { toHex, fromHex };
