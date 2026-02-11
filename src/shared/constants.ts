/**
 * Certen Key Vault - Shared Constants
 */

// Extension version
export const VERSION = '1.0.0';

// Storage keys
export const STORAGE_KEY_VAULT = 'certen_vault_v1';
export const STORAGE_KEY_SETTINGS = 'certen_settings_v1';

// Default settings
export const DEFAULT_AUTO_LOCK_TIMEOUT = 15 * 60 * 1000; // 15 minutes
export const DEFAULT_NETWORK = 'testnet';

// Networks
export const NETWORKS = {
  devnet: {
    name: 'DevNet',
    accumulate: 'http://localhost:26660',
    ethereum: ''
  },
  testnet: {
    name: 'Testnet',
    accumulate: 'https://kermit.accumulatenetwork.io',
    ethereum: 'https://sepolia.infura.io/v3/'
  },
  mainnet: {
    name: 'Mainnet',
    accumulate: 'https://mainnet.accumulatenetwork.io',
    ethereum: 'https://mainnet.infura.io/v3/'
  }
} as const;

// Crypto constants
export const PBKDF2_ITERATIONS = 600000;
export const SALT_LENGTH = 32;
export const IV_LENGTH = 12;
export const KEY_LENGTH = 32;

// BIP-44 coin types
export const ACCUMULATE_COIN_TYPE = 540;
export const ETHEREUM_COIN_TYPE = 60;

// RPC Methods
export const RPC_METHODS = {
  // Connection
  REQUEST_ACCOUNTS: 'acc_requestAccounts',
  GET_ACCOUNTS: 'acc_getAccounts',
  DISCONNECT: 'acc_disconnect',

  // Signing
  SIGN_TRANSACTION: 'acc_signTransaction',
  SIGN_HASH: 'acc_signHash',
  ETH_SIGN_HASH: 'eth_signHash',
  CERTEN_SIGN_INTENT: 'certen_signIntent',

  // Operations
  SEND_TOKENS: 'acc_sendTokens',
  ADD_CREDITS: 'acc_addCredits',

  // Query
  QUERY_ACCOUNT: 'acc_queryAccount',
  GET_BALANCE: 'acc_getBalance',
  GET_CREDITS: 'acc_getCredits',

  // Bridge
  BRIDGE_TO_EVM: 'certen_bridgeToEVM',
  GET_BRIDGE_STATUS: 'certen_getBridgeStatus'
} as const;

// Error codes
export const ERROR_CODES = {
  USER_REJECTED: 4001,
  UNAUTHORIZED: 4100,
  UNSUPPORTED_METHOD: 4200,
  DISCONNECTED: 4900,
  CHAIN_DISCONNECTED: 4901,
  INTERNAL_ERROR: -32603,
  INVALID_PARAMS: -32602,
  METHOD_NOT_FOUND: -32601,
  INVALID_REQUEST: -32600,
  PARSE_ERROR: -32700
} as const;
