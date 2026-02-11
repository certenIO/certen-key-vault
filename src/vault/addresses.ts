/**
 * Certen Key Vault - Multi-Chain Address Derivation
 *
 * Derives addresses for various blockchain networks from public keys.
 * Supports ED25519 and secp256k1 key types.
 */

import { sha256 } from '@noble/hashes/sha256';
import { sha3_256 } from '@noble/hashes/sha3';
import { keccak_256 } from '@noble/hashes/sha3';
import { blake2b } from '@noble/hashes/blake2b';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { bech32 } from 'bech32';
import bs58 from 'bs58';
import { toHex } from './crypto';

// TRON mainnet address version byte
const TRON_ADDRESS_PREFIX = 0x41;

// =============================================================================
// Cosmos Address Prefixes
// =============================================================================

export const COSMOS_CHAIN_PREFIXES: Record<string, string> = {
  cosmos: 'cosmos',
  osmosis: 'osmo',
  neutron: 'neutron',
  injective: 'inj',
  celestia: 'celestia',
  stargaze: 'stars',
  juno: 'juno',
  akash: 'akash',
  terra: 'terra',
  evmos: 'evmos',
  dydx: 'dydx',
  sei: 'sei',
  noble: 'noble',
  kujira: 'kujira',
};

// =============================================================================
// Solana (ED25519)
// =============================================================================

/**
 * Derives a Solana address from an ED25519 public key.
 * Solana addresses are simply the Base58-encoded public key.
 *
 * @param ed25519PubKey - 32-byte ED25519 public key
 * @returns Base58-encoded Solana address
 */
export function getSolanaAddress(ed25519PubKey: Uint8Array): string {
  if (ed25519PubKey.length !== 32) {
    throw new Error('Solana address requires 32-byte ED25519 public key');
  }

  return bs58.encode(ed25519PubKey);
}

// =============================================================================
// Cosmos (secp256k1)
// =============================================================================

/**
 * Derives a Cosmos-SDK address from a compressed secp256k1 public key.
 * Uses RIPEMD160(SHA256(pubkey)) and Bech32 encoding.
 *
 * @param secp256k1Compressed - 33-byte compressed secp256k1 public key
 * @param prefix - Bech32 prefix (e.g., 'cosmos', 'osmo', 'neutron')
 * @returns Bech32-encoded address
 */
export function getCosmosAddress(secp256k1Compressed: Uint8Array, prefix: string): string {
  if (secp256k1Compressed.length !== 33) {
    throw new Error('Cosmos address requires 33-byte compressed secp256k1 public key');
  }

  // Hash: RIPEMD160(SHA256(pubkey))
  const sha256Hash = sha256(secp256k1Compressed);
  const addressBytes = ripemd160(sha256Hash);

  // Convert to 5-bit words for Bech32
  const words = bech32.toWords(addressBytes);

  return bech32.encode(prefix, words);
}

/**
 * Derives addresses for multiple Cosmos chains from a single public key.
 *
 * @param secp256k1Compressed - 33-byte compressed secp256k1 public key
 * @param chainIds - Array of chain identifiers (e.g., ['cosmos', 'osmosis', 'neutron'])
 * @returns Record of chain -> address
 */
export function getCosmosAddresses(
  secp256k1Compressed: Uint8Array,
  chainIds: string[] = Object.keys(COSMOS_CHAIN_PREFIXES)
): Record<string, string> {
  const addresses: Record<string, string> = {};

  for (const chainId of chainIds) {
    const prefix = COSMOS_CHAIN_PREFIXES[chainId];
    if (prefix) {
      addresses[chainId] = getCosmosAddress(secp256k1Compressed, prefix);
    }
  }

  return addresses;
}

// =============================================================================
// TRON (secp256k1)
// =============================================================================

/**
 * Computes a Base58Check checksum (double SHA256, take first 4 bytes).
 *
 * @param data - Data to checksum
 * @returns 4-byte checksum
 */
function base58CheckChecksum(data: Uint8Array): Uint8Array {
  const hash1 = sha256(data);
  const hash2 = sha256(hash1);
  return hash2.slice(0, 4);
}

/**
 * Encodes data with Base58Check (data + 4-byte checksum).
 *
 * @param data - Data to encode (including version byte)
 * @returns Base58Check encoded string
 */
function base58CheckEncode(data: Uint8Array): string {
  const checksum = base58CheckChecksum(data);
  const dataWithChecksum = new Uint8Array(data.length + 4);
  dataWithChecksum.set(data, 0);
  dataWithChecksum.set(checksum, data.length);
  return bs58.encode(dataWithChecksum);
}

/**
 * Derives a TRON address from an uncompressed secp256k1 public key.
 * TRON uses: Keccak256(pubkey[1:65]) -> last 20 bytes -> prefix 0x41 -> Base58Check
 *
 * @param secp256k1Uncompressed - 65-byte uncompressed secp256k1 public key (with 0x04 prefix)
 * @returns Base58Check encoded TRON address (starts with 'T')
 */
export function getTronAddress(secp256k1Uncompressed: Uint8Array): string {
  if (secp256k1Uncompressed.length !== 65) {
    throw new Error('TRON address requires 65-byte uncompressed secp256k1 public key');
  }

  // Remove the 0x04 prefix (first byte) and hash the remaining 64 bytes
  const pubKeyWithoutPrefix = secp256k1Uncompressed.slice(1);
  const hash = keccak_256(pubKeyWithoutPrefix);

  // Take last 20 bytes
  const addressBytes = hash.slice(12);

  // Add TRON prefix (0x41 for mainnet)
  const addressWithPrefix = new Uint8Array(21);
  addressWithPrefix[0] = TRON_ADDRESS_PREFIX;
  addressWithPrefix.set(addressBytes, 1);

  // Base58Check encode
  return base58CheckEncode(addressWithPrefix);
}

// =============================================================================
// Aptos (ED25519)
// =============================================================================

/**
 * Derives an Aptos address from an ED25519 public key.
 * Aptos uses SHA3-256(pubkey || 0x00) where 0x00 indicates single-key scheme.
 *
 * @param ed25519PubKey - 32-byte ED25519 public key
 * @returns 0x-prefixed hex address
 */
export function getAptosAddress(ed25519PubKey: Uint8Array): string {
  if (ed25519PubKey.length !== 32) {
    throw new Error('Aptos address requires 32-byte ED25519 public key');
  }

  // Aptos single-key scheme: SHA3-256(pubkey || 0x00)
  const input = new Uint8Array(33);
  input.set(ed25519PubKey, 0);
  input[32] = 0x00; // Single-key scheme identifier

  const hash = sha3_256(input);
  return '0x' + toHex(hash);
}

// =============================================================================
// Sui (ED25519)
// =============================================================================

/**
 * Derives a Sui address from an ED25519 public key.
 * Sui uses Blake2b(0x00 || pubkey) where 0x00 indicates ED25519 scheme.
 *
 * @param ed25519PubKey - 32-byte ED25519 public key
 * @returns 0x-prefixed hex address
 */
export function getSuiAddress(ed25519PubKey: Uint8Array): string {
  if (ed25519PubKey.length !== 32) {
    throw new Error('Sui address requires 32-byte ED25519 public key');
  }

  // Sui scheme: Blake2b(0x00 || pubkey), 32 bytes output
  const input = new Uint8Array(33);
  input[0] = 0x00; // ED25519 scheme flag
  input.set(ed25519PubKey, 1);

  const hash = blake2b(input, { dkLen: 32 });
  return '0x' + toHex(hash);
}

// =============================================================================
// TON (ED25519)
// =============================================================================

/**
 * Derives a raw TON address from an ED25519 public key.
 * This returns the workchain:hash format.
 *
 * Note: Full TON addresses require additional wallet contract logic.
 * This returns a simplified hash-based identifier.
 *
 * @param ed25519PubKey - 32-byte ED25519 public key
 * @returns Address in format "0:hash" (workchain 0, masterchain)
 */
export function getTonAddress(ed25519PubKey: Uint8Array): string {
  if (ed25519PubKey.length !== 32) {
    throw new Error('TON address requires 32-byte ED25519 public key');
  }

  // Simple hash-based identifier (workchain 0)
  // Note: Real TON addresses are derived from wallet contract state init
  const hash = sha256(ed25519PubKey);
  return '0:' + toHex(hash);
}

// =============================================================================
// NEAR (ED25519)
// =============================================================================

/**
 * Derives a NEAR implicit account address from an ED25519 public key.
 * NEAR implicit accounts are just the hex-encoded public key.
 *
 * @param ed25519PubKey - 32-byte ED25519 public key
 * @returns Hex-encoded public key (64 characters)
 */
export function getNearAddress(ed25519PubKey: Uint8Array): string {
  if (ed25519PubKey.length !== 32) {
    throw new Error('NEAR address requires 32-byte ED25519 public key');
  }

  return toHex(ed25519PubKey);
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Computes all available addresses for an ED25519 public key.
 *
 * @param ed25519PubKey - 32-byte ED25519 public key
 * @returns Record of chain -> address for ED25519-compatible chains
 */
export function getED25519ChainAddresses(ed25519PubKey: Uint8Array): Record<string, string> {
  return {
    solana: getSolanaAddress(ed25519PubKey),
    aptos: getAptosAddress(ed25519PubKey),
    sui: getSuiAddress(ed25519PubKey),
    ton: getTonAddress(ed25519PubKey),
    near: getNearAddress(ed25519PubKey),
  };
}

/**
 * Computes all available addresses for a compressed secp256k1 public key.
 *
 * @param secp256k1Compressed - 33-byte compressed secp256k1 public key
 * @returns Record of chain -> address for secp256k1-compatible chains
 */
export function getSecp256k1ChainAddresses(secp256k1Compressed: Uint8Array): Record<string, string> {
  const cosmosAddresses = getCosmosAddresses(secp256k1Compressed);

  return {
    ...cosmosAddresses,
  };
}

/**
 * Validates a Bech32-encoded Cosmos address.
 *
 * @param address - Bech32 address to validate
 * @returns true if valid
 */
export function isValidCosmosAddress(address: string): boolean {
  try {
    const decoded = bech32.decode(address);
    const data = bech32.fromWords(decoded.words);
    return data.length === 20;
  } catch {
    return false;
  }
}

/**
 * Validates a Solana address (Base58-encoded ED25519 public key).
 *
 * @param address - Base58 address to validate
 * @returns true if valid
 */
export function isValidSolanaAddress(address: string): boolean {
  try {
    const decoded = bs58.decode(address);
    return decoded.length === 32;
  } catch {
    return false;
  }
}

/**
 * Validates a TRON address (Base58Check with 0x41 prefix).
 * Valid TRON mainnet addresses start with 'T'.
 *
 * @param address - Base58Check address to validate
 * @returns true if valid
 */
export function isValidTronAddress(address: string): boolean {
  try {
    // TRON addresses start with 'T'
    if (!address.startsWith('T')) {
      return false;
    }

    const decoded = bs58.decode(address);
    // Should be 25 bytes: 1 byte prefix + 20 bytes address + 4 bytes checksum
    if (decoded.length !== 25) {
      return false;
    }

    // Check prefix byte (0x41 for mainnet)
    if (decoded[0] !== TRON_ADDRESS_PREFIX) {
      return false;
    }

    // Verify checksum
    const data = decoded.slice(0, 21);
    const providedChecksum = decoded.slice(21);
    const computedChecksum = base58CheckChecksum(data);

    // Compare checksums
    for (let i = 0; i < 4; i++) {
      if (providedChecksum[i] !== computedChecksum[i]) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Extracts the Bech32 prefix from a Cosmos address.
 *
 * @param address - Bech32 address
 * @returns prefix string or null if invalid
 */
export function getCosmosAddressPrefix(address: string): string | null {
  try {
    const decoded = bech32.decode(address);
    return decoded.prefix;
  } catch {
    return null;
  }
}
