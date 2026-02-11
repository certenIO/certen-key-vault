/**
 * Certen Key Vault - CREATE2 Address Prediction
 *
 * Predicts EVM contract addresses deployed via CREATE2 opcode.
 * Used for ERC-4337 account abstraction address prediction.
 */

import { keccak_256 } from '@noble/hashes/sha3';
import { toHex, fromHex } from './crypto';
import { CERTEN_CONTRACTS, getContracts, isChainDeployed } from '../config/contracts';

// =============================================================================
// Types
// =============================================================================

export interface Create2Params {
  factory: string;          // Factory contract address (0x...)
  salt: string;             // 32-byte salt (0x...)
  initCodeHash: string;     // Keccak256 hash of init code (0x...)
}

export interface CertenAccountParams {
  factory: string;          // CertenAccountFactory address
  implementation: string;   // CertenAccountV2 implementation address
  adiUrl: string;           // Accumulate ADI URL
  ownerPubKey: string;      // Owner's public key (hex)
  chainId?: number;         // Optional chain ID for salt
}

// =============================================================================
// Generic CREATE2
// =============================================================================

/**
 * Computes a CREATE2 address.
 *
 * CREATE2 address = keccak256(0xff ++ factory ++ salt ++ initCodeHash)[12:]
 *
 * @param factory - Factory contract address (0x-prefixed)
 * @param salt - 32-byte salt (0x-prefixed hex)
 * @param initCodeHash - Keccak256 of init code (0x-prefixed hex)
 * @returns 0x-prefixed address
 */
export function computeCreate2Address(
  factory: string,
  salt: string,
  initCodeHash: string
): string {
  // Normalize addresses and hashes
  const factoryBytes = fromHex(normalizeHex(factory));
  const saltBytes = fromHex(normalizeHex(salt));
  const initCodeHashBytes = fromHex(normalizeHex(initCodeHash));

  if (factoryBytes.length !== 20) {
    throw new Error('Factory address must be 20 bytes');
  }
  if (saltBytes.length !== 32) {
    throw new Error('Salt must be 32 bytes');
  }
  if (initCodeHashBytes.length !== 32) {
    throw new Error('Init code hash must be 32 bytes');
  }

  // Construct: 0xff ++ factory ++ salt ++ initCodeHash
  const data = new Uint8Array(1 + 20 + 32 + 32);
  data[0] = 0xff;
  data.set(factoryBytes, 1);
  data.set(saltBytes, 21);
  data.set(initCodeHashBytes, 53);

  // Hash and take last 20 bytes
  const hash = keccak_256(data);
  const address = hash.slice(12);

  return '0x' + toHex(address);
}

/**
 * Computes the keccak256 hash of init code.
 *
 * @param initCode - Init code (0x-prefixed hex)
 * @returns 0x-prefixed keccak256 hash
 */
export function hashInitCode(initCode: string): string {
  const bytes = fromHex(normalizeHex(initCode));
  const hash = keccak_256(bytes);
  return '0x' + toHex(hash);
}

// =============================================================================
// Certen Account Factory
// =============================================================================

/**
 * Generates a salt for CertenAccountV2 deployment.
 * Salt is derived from the ADI URL and owner public key.
 *
 * @param adiUrl - Accumulate ADI URL (e.g., "acc://myadi.acme")
 * @param ownerPubKey - Owner's public key (hex)
 * @param chainId - Optional chain ID (default: 0)
 * @returns 32-byte salt as 0x-prefixed hex
 */
export function generateCertenAccountSalt(
  adiUrl: string,
  ownerPubKey: string,
  chainId: number = 0
): string {
  // Normalize ADI URL
  const normalizedAdi = adiUrl.toLowerCase().replace(/\/$/, '');

  // Create salt input: keccak256(adiUrl ++ ownerPubKey ++ chainId)
  const encoder = new TextEncoder();
  const adiBytes = encoder.encode(normalizedAdi);
  const pubKeyBytes = fromHex(normalizeHex(ownerPubKey));
  const chainIdBytes = numberToBytes32(chainId);

  const input = new Uint8Array(adiBytes.length + pubKeyBytes.length + 32);
  input.set(adiBytes, 0);
  input.set(pubKeyBytes, adiBytes.length);
  input.set(chainIdBytes, adiBytes.length + pubKeyBytes.length);

  const salt = keccak_256(input);
  return '0x' + toHex(salt);
}

/**
 * Computes the init code hash for a minimal proxy (EIP-1167 clone).
 * This is used when the factory deploys clones of an implementation.
 *
 * @param implementation - Implementation contract address
 * @returns 0x-prefixed keccak256 hash
 */
export function getMinimalProxyInitCodeHash(implementation: string): string {
  const implBytes = fromHex(normalizeHex(implementation));
  if (implBytes.length !== 20) {
    throw new Error('Implementation address must be 20 bytes');
  }

  // EIP-1167 minimal proxy creation code:
  // 3d602d80600a3d3981f3363d3d373d3d3d363d73{impl}5af43d82803e903d91602b57fd5bf3
  const prefix = fromHex('3d602d80600a3d3981f3363d3d373d3d3d363d73');
  const suffix = fromHex('5af43d82803e903d91602b57fd5bf3');

  const creationCode = new Uint8Array(prefix.length + 20 + suffix.length);
  creationCode.set(prefix, 0);
  creationCode.set(implBytes, prefix.length);
  creationCode.set(suffix, prefix.length + 20);

  const hash = keccak_256(creationCode);
  return '0x' + toHex(hash);
}

/**
 * Predicts a CertenAccountV2 address.
 *
 * @param params - CertenAccountParams
 * @returns Predicted 0x-prefixed address
 */
export function predictCertenAccountAddress(params: CertenAccountParams): string {
  const salt = generateCertenAccountSalt(
    params.adiUrl,
    params.ownerPubKey,
    params.chainId
  );

  const initCodeHash = getMinimalProxyInitCodeHash(params.implementation);

  return computeCreate2Address(params.factory, salt, initCodeHash);
}

// =============================================================================
// Known Factory Addresses (derived from centralized config)
// =============================================================================

/**
 * Implementation addresses for CertenAccountV2 by chain ID.
 * These are the logic contracts that get proxied via EIP-1167 clones.
 *
 * Note: Implementation addresses must be added after deployment.
 * The factory address comes from the centralized contracts config.
 */
export const CERTEN_IMPLEMENTATIONS: Record<number, string | null> = {
  // Mainnets
  1: null,       // Ethereum - not yet deployed
  42161: null,   // Arbitrum - not yet deployed
  43114: null,   // Avalanche - not yet deployed
  8453: null,    // Base - not yet deployed
  56: null,      // BSC - not yet deployed
  10: null,      // Optimism - not yet deployed
  137: null,     // Polygon - not yet deployed
  324: null,     // zkSync - not yet deployed
  1284: null,    // Moonbeam - not yet deployed

  // Testnets
  11155111: null, // Ethereum Sepolia - TODO: Add after deployment
  421614: null,   // Arbitrum Sepolia - not yet deployed
  43113: null,    // Avalanche Fuji - not yet deployed
  84532: null,    // Base Sepolia - not yet deployed
  97: null,       // BSC Testnet - not yet deployed
  11155420: null, // Optimism Sepolia - not yet deployed
  80002: null,    // Polygon Amoy - not yet deployed
  300: null,      // zkSync Sepolia - not yet deployed
  1287: null,     // Moonbeam Moonbase Alpha - not yet deployed
};

/**
 * Get factory deployment info for a chain.
 * Factory address comes from centralized config, implementation from local mapping.
 */
export function getFactoryDeployment(chainId: number): {
  factory: string | null;
  implementation: string | null;
} | null {
  const contracts = getContracts(chainId);
  if (!contracts) return null;

  return {
    factory: contracts.accountFactory,
    implementation: CERTEN_IMPLEMENTATIONS[chainId] || null,
  };
}

/**
 * Legacy export for backwards compatibility.
 * @deprecated Use getFactoryDeployment() instead
 */
export const CERTEN_FACTORIES: Record<number, {
  factory: string;
  implementation: string;
}> = Object.keys(CERTEN_CONTRACTS).reduce((acc, key) => {
  const chainId = Number(key);
  const contracts = CERTEN_CONTRACTS[chainId]?.contracts;
  const implementation = CERTEN_IMPLEMENTATIONS[chainId];

  if (contracts?.accountFactory && implementation) {
    acc[chainId] = {
      factory: contracts.accountFactory,
      implementation: implementation,
    };
  }
  return acc;
}, {} as Record<number, { factory: string; implementation: string }>);

/**
 * Predicts a Certen account address for a specific chain.
 *
 * @param adiUrl - Accumulate ADI URL
 * @param ownerPubKey - Owner's public key (hex)
 * @param chainId - EVM chain ID
 * @returns Predicted address or null if chain not supported or not fully deployed
 */
export function predictCertenAccountForChain(
  adiUrl: string,
  ownerPubKey: string,
  chainId: number
): string | null {
  const deployment = getFactoryDeployment(chainId);

  // Need both factory and implementation to predict address
  if (!deployment || !deployment.factory || !deployment.implementation) {
    return null;
  }

  return predictCertenAccountAddress({
    factory: deployment.factory,
    implementation: deployment.implementation,
    adiUrl,
    ownerPubKey,
    chainId,
  });
}

/**
 * Check if CREATE2 address prediction is available for a chain.
 * Requires both factory and implementation contracts to be deployed.
 */
export function canPredictAddressForChain(chainId: number): boolean {
  const deployment = getFactoryDeployment(chainId);
  return !!(deployment?.factory && deployment?.implementation);
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Normalizes a hex string by removing 0x prefix.
 */
function normalizeHex(hex: string): string {
  return hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
}

/**
 * Converts a number to a 32-byte big-endian representation.
 */
function numberToBytes32(num: number): Uint8Array {
  const bytes = new Uint8Array(32);
  let n = BigInt(num);

  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(n & BigInt(0xff));
    n = n >> BigInt(8);
  }

  return bytes;
}

/**
 * Validates an EVM address format.
 */
export function isValidEvmAddress(address: string): boolean {
  if (!address.startsWith('0x') && !address.startsWith('0X')) {
    return false;
  }
  const hex = address.slice(2);
  if (hex.length !== 40) {
    return false;
  }
  return /^[0-9a-fA-F]+$/.test(hex);
}

/**
 * Checksums an EVM address (EIP-55).
 */
export function checksumAddress(address: string): string {
  const normalized = normalizeHex(address).toLowerCase();
  const hash = keccak_256(new TextEncoder().encode(normalized));
  const hashHex = toHex(hash);

  let result = '0x';
  for (let i = 0; i < normalized.length; i++) {
    if (parseInt(hashHex[i], 16) >= 8) {
      result += normalized[i].toUpperCase();
    } else {
      result += normalized[i];
    }
  }

  return result;
}
