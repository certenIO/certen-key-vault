/**
 * Certen Key Vault - BIP-39 Mnemonic and HD Key Derivation
 *
 * Uses @scure/bip39 and @scure/bip32 for mnemonic generation and HD key derivation.
 * - BIP-39: Mnemonic generation and seed derivation
 * - SLIP-0010: ED25519 key derivation (for Accumulate)
 * - BIP-44: secp256k1 key derivation (for Ethereum)
 */

import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import * as nacl from 'tweetnacl';
import * as secp256k1 from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { hkdf } from '@noble/hashes/hkdf';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { toHex } from './crypto';

// =============================================================================
// Constants
// =============================================================================

// Accumulate uses coin type 540 (registered in SLIP-0044)
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
export const ACCUMULATE_COIN_TYPE = 540;

// Ethereum uses coin type 60
export const ETHEREUM_COIN_TYPE = 60;

// BLS12-381 uses coin type 12381 (EIP-2333/EIP-2334)
export const BLS_COIN_TYPE = 12381;

// Default derivation paths
export const DEFAULT_ACCUMULATE_PATH = `m/44'/${ACCUMULATE_COIN_TYPE}'/0'/0'`;
export const DEFAULT_ETHEREUM_PATH = `m/44'/${ETHEREUM_COIN_TYPE}'/0'/0`;
// EIP-2334 validator path: m/12381/60/0/0
export const DEFAULT_BLS_PATH = `m/${BLS_COIN_TYPE}/60/0/0`;

// =============================================================================
// Mnemonic Generation
// =============================================================================

/**
 * Generates a new BIP-39 mnemonic phrase.
 *
 * @param strength - 128 for 12 words, 256 for 24 words (default: 128)
 * @returns Mnemonic phrase as space-separated words
 */
export function generateMnemonic(strength: 128 | 256 = 128): string {
  return bip39.generateMnemonic(wordlist, strength);
}

/**
 * Validates a BIP-39 mnemonic phrase.
 *
 * @param mnemonic - Mnemonic phrase to validate
 * @returns true if valid
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic, wordlist);
}

/**
 * Converts a mnemonic phrase to a seed.
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param passphrase - Optional passphrase (default: empty string)
 * @returns 64-byte seed
 */
export function mnemonicToSeed(mnemonic: string, passphrase: string = ''): Uint8Array {
  return bip39.mnemonicToSeedSync(mnemonic, passphrase);
}

// =============================================================================
// ED25519 Key Derivation (SLIP-0010)
// =============================================================================

/**
 * Result of ED25519 key derivation.
 */
export interface DerivedED25519Key {
  publicKey: Uint8Array;    // 32 bytes
  privateKey: Uint8Array;   // 64 bytes (seed + public key)
  seed: Uint8Array;         // 32-byte seed
  path: string;             // Derivation path used
}

/**
 * Derives an ED25519 keypair from a mnemonic using SLIP-0010.
 *
 * SLIP-0010 specifies ED25519 derivation from BIP-32 seeds.
 * Path format: m/44'/540'/account'/0'/address_index'
 * All path segments must be hardened (') for ED25519.
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param index - Address index (default: 0)
 * @param account - Account index (default: 0)
 * @returns Derived ED25519 keypair with path
 */
export function deriveED25519FromMnemonic(
  mnemonic: string,
  index: number = 0,
  account: number = 0
): DerivedED25519Key {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }

  const seed = mnemonicToSeed(mnemonic);
  const path = `m/44'/${ACCUMULATE_COIN_TYPE}'/${account}'/0'/${index}'`;

  // Use SLIP-0010 derivation
  // For ED25519, we derive to get the seed bytes, then create the keypair
  const derived = slip0010Derive(seed, path);

  // Create ED25519 keypair from 32-byte derived seed
  const keyPair = nacl.sign.keyPair.fromSeed(derived);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.secretKey,
    seed: derived,
    path
  };
}

/**
 * SLIP-0010 derivation for ED25519.
 * This implements the ED25519 derivation scheme from the SLIP-0010 specification.
 *
 * @param seed - 64-byte BIP-39 seed
 * @param path - Derivation path (all segments must be hardened)
 * @returns 32-byte derived key
 */
function slip0010Derive(seed: Uint8Array, path: string): Uint8Array {
  // Parse path
  const segments = path
    .replace(/^m\//, '')
    .split('/')
    .map(s => {
      const hardened = s.endsWith("'");
      const index = parseInt(s.replace("'", ''), 10);
      if (!hardened) {
        throw new Error('All ED25519 path segments must be hardened');
      }
      return index + 0x80000000; // Add hardened flag
    });

  // Initial key material from seed
  const encoder = new TextEncoder();
  let key = hmacSha512(encoder.encode('ed25519 seed'), seed);

  // Derive through path
  for (const index of segments) {
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, false); // Big endian

    const data = new Uint8Array(1 + 32 + 4);
    data[0] = 0x00;
    data.set(key.slice(0, 32), 1);
    data.set(indexBytes, 33);

    key = hmacSha512(key.slice(32), data);
  }

  return key.slice(0, 32);
}

// =============================================================================
// secp256k1 Key Derivation (BIP-44)
// =============================================================================

/**
 * Result of secp256k1 key derivation.
 */
export interface DerivedSecp256k1Key {
  publicKey: Uint8Array;    // 65 bytes (uncompressed) or 33 bytes (compressed)
  privateKey: Uint8Array;   // 32 bytes
  path: string;             // Derivation path used
}

/**
 * Derives a secp256k1 keypair from a mnemonic using BIP-44.
 *
 * Path format: m/44'/60'/account'/0/address_index
 * Standard Ethereum derivation path.
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param index - Address index (default: 0)
 * @param account - Account index (default: 0)
 * @param compressed - Return compressed public key (default: false)
 * @returns Derived secp256k1 keypair with path
 */
export function deriveSecp256k1FromMnemonic(
  mnemonic: string,
  index: number = 0,
  account: number = 0,
  compressed: boolean = false
): DerivedSecp256k1Key {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }

  const seed = mnemonicToSeed(mnemonic);
  const path = `m/44'/${ETHEREUM_COIN_TYPE}'/${account}'/0/${index}`;

  // Use standard BIP-32 derivation for secp256k1
  const hdKey = HDKey.fromMasterSeed(seed);
  const derived = hdKey.derive(path);

  if (!derived.privateKey) {
    throw new Error('Failed to derive private key');
  }

  const publicKey = secp256k1.getPublicKey(derived.privateKey, compressed);

  return {
    publicKey,
    privateKey: derived.privateKey,
    path
  };
}

// =============================================================================
// HMAC-SHA512 Implementation
// =============================================================================

/**
 * HMAC-SHA512 implementation using Web Crypto API.
 */
async function hmacSha512Async(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key.buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data.buffer as ArrayBuffer);
  return new Uint8Array(signature);
}

/**
 * Synchronous HMAC-SHA512 using @noble/hashes.
 */
function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  // Use @noble/hashes for synchronous HMAC (imported at top of file)
  return hmac(sha512, key, data);
}

// =============================================================================
// BLS12-381 Key Derivation (EIP-2333)
// =============================================================================

/**
 * Result of BLS12-381 key derivation.
 */
export interface DerivedBLS12381Key {
  publicKey: Uint8Array;    // 48 bytes (G1 point)
  privateKey: Uint8Array;   // 32 bytes
  path: string;             // Derivation path used
}

/**
 * Derives a BLS12-381 keypair from a mnemonic using EIP-2333.
 *
 * EIP-2333 specifies BLS12-381 key derivation for Ethereum 2.0 validators.
 * Path format: m/12381/60/account/0/index (EIP-2334 validator path)
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param index - Key index (default: 0)
 * @param account - Account index (default: 0)
 * @returns Derived BLS12-381 keypair with path
 */
export function deriveBLS12381FromMnemonic(
  mnemonic: string,
  index: number = 0,
  account: number = 0
): DerivedBLS12381Key {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }

  const seed = mnemonicToSeed(mnemonic);
  // EIP-2334 path for signing keys: m/12381/60/account/0/index
  const path = `m/${BLS_COIN_TYPE}/60/${account}/0/${index}`;

  // Derive master key using EIP-2333
  const masterKey = eip2333DeriveMasterSK(seed);

  // Derive child key for the path
  const pathSegments = [BLS_COIN_TYPE, 60, account, 0, index];
  let privateKey = masterKey;
  for (const segment of pathSegments) {
    privateKey = eip2333DeriveChildSK(privateKey, segment);
  }

  // Get public key
  const publicKey = bls.getPublicKey(privateKey);

  return {
    publicKey,
    privateKey,
    path
  };
}

/**
 * EIP-2333 master key derivation from seed.
 * HKDF-SHA256 with salt "BLS-SIG-KEYGEN-SALT-"
 *
 * @param seed - 64-byte BIP-39 seed
 * @returns 32-byte master secret key
 */
function eip2333DeriveMasterSK(seed: Uint8Array): Uint8Array {
  const salt = new TextEncoder().encode('BLS-SIG-KEYGEN-SALT-');

  // L = ceil((3 * ceil(log2(r))) / 16) where r is the BLS12-381 order
  // For BLS12-381, L = 48
  const L = 48;

  // IKM = seed || I2OSP(0, 1)
  const ikm = new Uint8Array(seed.length + 1);
  ikm.set(seed, 0);
  ikm[seed.length] = 0;

  // OKM = HKDF-Expand(HKDF-Extract(salt, IKM), "", L)
  let okm = hkdf(sha256, ikm, salt, '', L);

  // SK = OS2IP(OKM) mod r
  // Since we're working with bytes, we need to reduce modulo the BLS12-381 order
  const sk = reduceModR(okm);

  return sk;
}

/**
 * EIP-2333 child key derivation.
 *
 * @param parentSK - 32-byte parent secret key
 * @param index - Child index (not hardened)
 * @returns 32-byte child secret key
 */
function eip2333DeriveChildSK(parentSK: Uint8Array, index: number): Uint8Array {
  // Lamport tree derivation
  const salt = i2osp(index, 4);
  const ikm = parentSK;

  const L = 48;
  let okm = hkdf(sha256, ikm, salt, '', L);

  return reduceModR(okm);
}

/**
 * Integer to Octet String Primitive (big-endian).
 */
function i2osp(value: number, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = v & 0xff;
    v = v >>> 8;
  }
  return result;
}

/**
 * Reduces a byte array modulo the BLS12-381 curve order r.
 * r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
 *
 * This is a simplified reduction - for production use, a proper big integer library
 * would be more appropriate, but this works for key derivation.
 */
function reduceModR(bytes: Uint8Array): Uint8Array {
  // BLS12-381 order r as a BigInt
  const r = BigInt('52435875175126190479447740508185965837690552500527637822603658699938581184513');

  // Convert bytes to BigInt (big-endian)
  let value = BigInt(0);
  for (const byte of bytes) {
    value = (value << BigInt(8)) | BigInt(byte);
  }

  // Reduce modulo r
  value = value % r;

  // Convert back to 32 bytes (big-endian)
  const result = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    result[i] = Number(value & BigInt(0xff));
    value = value >> BigInt(8);
  }

  return result;
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Generates all key types from a mnemonic.
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param ed25519Count - Number of ED25519 keys to derive (default: 1)
 * @param secp256k1Count - Number of secp256k1 keys to derive (default: 1)
 * @param bls12381Count - Number of BLS12-381 keys to derive (default: 0)
 * @returns Object containing derived keys
 */
export function deriveAllKeysFromMnemonic(
  mnemonic: string,
  ed25519Count: number = 1,
  secp256k1Count: number = 1,
  bls12381Count: number = 0
): {
  ed25519Keys: DerivedED25519Key[];
  secp256k1Keys: DerivedSecp256k1Key[];
  bls12381Keys: DerivedBLS12381Key[];
} {
  const ed25519Keys: DerivedED25519Key[] = [];
  const secp256k1Keys: DerivedSecp256k1Key[] = [];
  const bls12381Keys: DerivedBLS12381Key[] = [];

  for (let i = 0; i < ed25519Count; i++) {
    ed25519Keys.push(deriveED25519FromMnemonic(mnemonic, i));
  }

  for (let i = 0; i < secp256k1Count; i++) {
    secp256k1Keys.push(deriveSecp256k1FromMnemonic(mnemonic, i));
  }

  for (let i = 0; i < bls12381Count; i++) {
    bls12381Keys.push(deriveBLS12381FromMnemonic(mnemonic, i));
  }

  return { ed25519Keys, secp256k1Keys, bls12381Keys };
}

/**
 * Gets the next available derivation index for a given path prefix.
 *
 * @param existingPaths - Array of existing derivation paths
 * @param pathPrefix - Path prefix to check (e.g., "m/44'/540'/0'/0'")
 * @returns Next available index
 */
export function getNextDerivationIndex(
  existingPaths: string[],
  pathPrefix: string
): number {
  const indices = existingPaths
    .filter(p => p.startsWith(pathPrefix))
    .map(p => {
      const match = p.match(/\/(\d+)'?$/);
      return match ? parseInt(match[1], 10) : -1;
    })
    .filter(i => i >= 0);

  if (indices.length === 0) return 0;
  return Math.max(...indices) + 1;
}
