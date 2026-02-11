/**
 * Certen Protocol Contract Addresses - Key Vault Extension
 *
 * This file contains all deployed contract addresses for the Certen protocol
 * across all supported EVM blockchains (mainnets and testnets).
 *
 * Contract Types:
 * - accountFactory: Creates new Certen smart accounts (ERC-4337 compatible)
 * - anchor: CERTEN_ANCHOR contract for cross-chain identity anchoring
 * - blsZkVerifier: BLS12-381 zero-knowledge signature verifier
 *
 * Note: null values indicate the contract has not yet been deployed to that chain.
 */

export interface ChainContracts {
  accountFactory: string | null;
  anchor: string | null;
  blsZkVerifier: string | null;
}

export interface ChainContractConfig {
  chainId: number;           // EVM Chain ID
  name: string;              // Human-readable chain name
  isTestnet: boolean;        // Whether this is a testnet
  explorerUrl: string;       // Block explorer base URL
  contracts: ChainContracts;
}

/**
 * Standard ERC-4337 EntryPoint address (same across all EVM chains)
 */
export const ERC4337_ENTRYPOINT = '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789';

/**
 * All Certen protocol contract addresses by chain ID (EVM chains only)
 */
export const CERTEN_CONTRACTS: Record<number, ChainContractConfig> = {
  // ============================================================
  // EVM MAINNETS
  // ============================================================
  1: {
    chainId: 1,
    name: 'Ethereum',
    isTestnet: false,
    explorerUrl: 'https://etherscan.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  42161: {
    chainId: 42161,
    name: 'Arbitrum',
    isTestnet: false,
    explorerUrl: 'https://arbiscan.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  43114: {
    chainId: 43114,
    name: 'Avalanche',
    isTestnet: false,
    explorerUrl: 'https://snowtrace.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  8453: {
    chainId: 8453,
    name: 'Base',
    isTestnet: false,
    explorerUrl: 'https://basescan.org',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  56: {
    chainId: 56,
    name: 'Binance Smart Chain',
    isTestnet: false,
    explorerUrl: 'https://bscscan.com',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  10: {
    chainId: 10,
    name: 'Optimism',
    isTestnet: false,
    explorerUrl: 'https://optimistic.etherscan.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  137: {
    chainId: 137,
    name: 'Polygon',
    isTestnet: false,
    explorerUrl: 'https://polygonscan.com',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  324: {
    chainId: 324,
    name: 'zkSync',
    isTestnet: false,
    explorerUrl: 'https://explorer.zksync.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  1284: {
    chainId: 1284,
    name: 'Moonbeam',
    isTestnet: false,
    explorerUrl: 'https://moonscan.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },

  // ============================================================
  // EVM TESTNETS
  // ============================================================
  11155111: {
    chainId: 11155111,
    name: 'Ethereum Sepolia',
    isTestnet: true,
    explorerUrl: 'https://sepolia.etherscan.io',
    contracts: {
      accountFactory: '0xbd9D33310358C8A10254175dD297e2CA8cd623c3',
      anchor: '0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98',
      blsZkVerifier: '0x631B6444216b981561034655349F8a28962DcC5F',
    },
  },
  421614: {
    chainId: 421614,
    name: 'Arbitrum Sepolia',
    isTestnet: true,
    explorerUrl: 'https://sepolia.arbiscan.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  43113: {
    chainId: 43113,
    name: 'Avalanche Fuji',
    isTestnet: true,
    explorerUrl: 'https://testnet.snowtrace.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  84532: {
    chainId: 84532,
    name: 'Base Sepolia',
    isTestnet: true,
    explorerUrl: 'https://sepolia-explorer.base.org',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  97: {
    chainId: 97,
    name: 'BSC Testnet',
    isTestnet: true,
    explorerUrl: 'https://testnet.bscscan.com',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  11155420: {
    chainId: 11155420,
    name: 'Optimism Sepolia',
    isTestnet: true,
    explorerUrl: 'https://sepolia-optimistic.etherscan.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  80002: {
    chainId: 80002,
    name: 'Polygon Amoy',
    isTestnet: true,
    explorerUrl: 'https://amoy.polygonscan.com',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  300: {
    chainId: 300,
    name: 'zkSync Sepolia',
    isTestnet: true,
    explorerUrl: 'https://sepolia.explorer.zksync.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
  1287: {
    chainId: 1287,
    name: 'Moonbeam Moonbase Alpha',
    isTestnet: true,
    explorerUrl: 'https://moonbase.moonscan.io',
    contracts: {
      accountFactory: null,
      anchor: null,
      blsZkVerifier: null,
    },
  },
};

// ============================================================
// HELPER FUNCTIONS
// ============================================================

/**
 * Get contract configuration for a specific chain
 */
export function getChainContracts(chainId: number): ChainContractConfig | null {
  return CERTEN_CONTRACTS[chainId] || null;
}

/**
 * Get just the contract addresses for a chain
 */
export function getContracts(chainId: number): ChainContracts | null {
  const config = CERTEN_CONTRACTS[chainId];
  return config ? config.contracts : null;
}

/**
 * Check if Certen contracts are deployed on a specific chain
 */
export function isChainDeployed(chainId: number): boolean {
  const config = CERTEN_CONTRACTS[chainId];
  if (!config) return false;
  const { contracts } = config;
  return !!(contracts.accountFactory && contracts.anchor && contracts.blsZkVerifier);
}

/**
 * Get all deployed chains (fully deployed only)
 */
export function getDeployedChains(): ChainContractConfig[] {
  return Object.values(CERTEN_CONTRACTS).filter(config => isChainDeployed(config.chainId));
}

/**
 * Get all deployed testnet chains
 */
export function getDeployedTestnets(): ChainContractConfig[] {
  return getDeployedChains().filter(config => config.isTestnet);
}

/**
 * Get all deployed mainnet chains
 */
export function getDeployedMainnets(): ChainContractConfig[] {
  return getDeployedChains().filter(config => !config.isTestnet);
}

/**
 * Get all supported chain IDs
 */
export function getSupportedChainIds(): number[] {
  return Object.keys(CERTEN_CONTRACTS).map(Number);
}

/**
 * Get contract explorer URL
 */
export function getContractExplorerUrl(
  chainId: number,
  contractType: keyof ChainContracts
): string | null {
  const config = CERTEN_CONTRACTS[chainId];
  if (!config) return null;

  const address = config.contracts[contractType];
  if (!address) return null;

  return `${config.explorerUrl}/address/${address}`;
}
