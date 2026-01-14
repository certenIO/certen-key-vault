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
import { sha512 } from '@noble/hashes/sha512';
import { toHex } from './crypto';

// =============================================================================
// Constants
// =============================================================================

// Accumulate uses coin type 540 (registered in SLIP-0044)
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
export const ACCUMULATE_COIN_TYPE = 540;

// Ethereum uses coin type 60
export const ETHEREUM_COIN_TYPE = 60;

// Default derivation paths
export const DEFAULT_ACCUMULATE_PATH = `m/44'/${ACCUMULATE_COIN_TYPE}'/0'/0'`;
export const DEFAULT_ETHEREUM_PATH = `m/44'/${ETHEREUM_COIN_TYPE}'/0'/0`;

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
// Utility Functions
// =============================================================================

/**
 * Generates all key types from a mnemonic.
 *
 * @param mnemonic - BIP-39 mnemonic phrase
 * @param ed25519Count - Number of ED25519 keys to derive (default: 1)
 * @param secp256k1Count - Number of secp256k1 keys to derive (default: 1)
 * @returns Object containing derived keys
 */
export function deriveAllKeysFromMnemonic(
  mnemonic: string,
  ed25519Count: number = 1,
  secp256k1Count: number = 1
): {
  ed25519Keys: DerivedED25519Key[];
  secp256k1Keys: DerivedSecp256k1Key[];
} {
  const ed25519Keys: DerivedED25519Key[] = [];
  const secp256k1Keys: DerivedSecp256k1Key[] = [];

  for (let i = 0; i < ed25519Count; i++) {
    ed25519Keys.push(deriveED25519FromMnemonic(mnemonic, i));
  }

  for (let i = 0; i < secp256k1Count; i++) {
    secp256k1Keys.push(deriveSecp256k1FromMnemonic(mnemonic, i));
  }

  return { ed25519Keys, secp256k1Keys };
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
