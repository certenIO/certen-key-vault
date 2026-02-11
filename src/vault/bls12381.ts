/**
 * Certen Key Vault - BLS12-381 Operations
 *
 * BLS12-381 cryptographic operations for validator keys and signature aggregation.
 * Uses @noble/curves for the underlying cryptographic primitives.
 */

import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { randomBytes, toHex, fromHex } from './crypto';

// =============================================================================
// Types
// =============================================================================

export interface BLS12381KeyPair {
  publicKey: Uint8Array;    // 48 bytes (compressed G1 point)
  privateKey: Uint8Array;   // 32 bytes
}

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generates a new BLS12-381 keypair.
 *
 * @returns BLS12381KeyPair with 32-byte private key and 48-byte public key
 */
export function generateBLS12381Key(): BLS12381KeyPair {
  const privateKey = randomBytes(32);
  const publicKey = bls.getPublicKey(privateKey);

  return {
    publicKey,
    privateKey
  };
}

/**
 * Creates a BLS12-381 keypair from an existing private key.
 *
 * @param privateKeyHex - Hex-encoded 32-byte private key
 * @returns BLS12381KeyPair
 */
export function bls12381FromPrivateKeyHex(privateKeyHex: string): BLS12381KeyPair {
  const privateKey = fromHex(privateKeyHex);
  if (privateKey.length !== 32) {
    throw new Error('BLS12-381 private key must be 32 bytes');
  }

  const publicKey = bls.getPublicKey(privateKey);

  return {
    publicKey,
    privateKey
  };
}

/**
 * Creates a BLS12-381 keypair from a 32-byte seed.
 *
 * @param seed - 32-byte seed
 * @returns BLS12381KeyPair
 */
export function bls12381FromSeed(seed: Uint8Array): BLS12381KeyPair {
  if (seed.length !== 32) {
    throw new Error('BLS12-381 seed must be 32 bytes');
  }

  const publicKey = bls.getPublicKey(seed);

  return {
    publicKey,
    privateKey: seed
  };
}

// =============================================================================
// Signing
// =============================================================================

/**
 * Signs a message hash with a BLS12-381 private key.
 *
 * @param hash - Hash to sign (will be hashed to curve)
 * @param privateKey - 32-byte private key
 * @returns 96-byte signature (G2 point)
 */
export function signBLS12381(hash: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return bls.sign(hash, privateKey);
}

/**
 * Signs a hex-encoded hash with a hex-encoded BLS12-381 private key.
 *
 * @param hashHex - Hex-encoded hash to sign
 * @param privateKeyHex - Hex-encoded 32-byte private key
 * @returns Hex-encoded 96-byte signature
 */
export function signBLS12381Hex(hashHex: string, privateKeyHex: string): string {
  const hash = fromHex(hashHex);
  const privateKey = fromHex(privateKeyHex);
  const signature = signBLS12381(hash, privateKey);
  return toHex(signature);
}

// =============================================================================
// Verification
// =============================================================================

/**
 * Verifies a BLS12-381 signature.
 *
 * @param message - Original message that was signed
 * @param signature - 96-byte signature
 * @param publicKey - 48-byte public key
 * @returns true if signature is valid
 */
export function verifyBLS12381(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return bls.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Verifies a BLS12-381 signature with hex-encoded inputs.
 *
 * @param messageHex - Hex-encoded message
 * @param signatureHex - Hex-encoded 96-byte signature
 * @param publicKeyHex - Hex-encoded 48-byte public key
 * @returns true if signature is valid
 */
export function verifyBLS12381Hex(
  messageHex: string,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    const message = fromHex(messageHex);
    const signature = fromHex(signatureHex);
    const publicKey = fromHex(publicKeyHex);
    return verifyBLS12381(message, signature, publicKey);
  } catch {
    return false;
  }
}

// =============================================================================
// Aggregation
// =============================================================================

/**
 * Aggregates multiple BLS12-381 signatures into a single signature.
 * This is the key feature of BLS - multiple signatures can be combined
 * for efficient batch verification.
 *
 * @param signatures - Array of 96-byte signatures
 * @returns Aggregated 96-byte signature
 */
export function aggregateSignatures(signatures: Uint8Array[]): Uint8Array {
  if (signatures.length === 0) {
    throw new Error('Cannot aggregate empty signature array');
  }

  return bls.aggregateSignatures(signatures);
}

/**
 * Aggregates multiple hex-encoded BLS12-381 signatures.
 *
 * @param signaturesHex - Array of hex-encoded signatures
 * @returns Hex-encoded aggregated signature
 */
export function aggregateSignaturesHex(signaturesHex: string[]): string {
  const signatures = signaturesHex.map(s => fromHex(s));
  const aggregated = aggregateSignatures(signatures);
  return toHex(aggregated);
}

/**
 * Aggregates multiple BLS12-381 public keys.
 *
 * @param publicKeys - Array of 48-byte public keys
 * @returns Aggregated 48-byte public key
 */
export function aggregatePublicKeys(publicKeys: Uint8Array[]): Uint8Array {
  if (publicKeys.length === 0) {
    throw new Error('Cannot aggregate empty public key array');
  }

  return bls.aggregatePublicKeys(publicKeys);
}

/**
 * Verifies an aggregated signature against multiple messages and public keys.
 *
 * @param messages - Array of messages (one per signer)
 * @param signature - Aggregated signature
 * @param publicKeys - Array of public keys (one per signer)
 * @returns true if the aggregated signature is valid
 */
export function verifyAggregate(
  messages: Uint8Array[],
  signature: Uint8Array,
  publicKeys: Uint8Array[]
): boolean {
  if (messages.length !== publicKeys.length) {
    throw new Error('Number of messages must match number of public keys');
  }

  try {
    return bls.verifyBatch(signature, messages, publicKeys);
  } catch {
    return false;
  }
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Gets the public key for a given private key.
 *
 * @param privateKey - 32-byte private key
 * @returns 48-byte public key
 */
export function getPublicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  return bls.getPublicKey(privateKey);
}

/**
 * Validates that a public key is on the BLS12-381 G1 curve.
 *
 * @param publicKey - 48-byte public key to validate
 * @returns true if the public key is valid
 */
export function isValidPublicKey(publicKey: Uint8Array): boolean {
  try {
    bls.G1.ProjectivePoint.fromHex(publicKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates that a signature is on the BLS12-381 G2 curve.
 *
 * @param signature - 96-byte signature to validate
 * @returns true if the signature is structurally valid
 */
export function isValidSignature(signature: Uint8Array): boolean {
  try {
    bls.G2.ProjectivePoint.fromHex(signature);
    return true;
  } catch {
    return false;
  }
}
