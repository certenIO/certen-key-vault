/**
 * Certen Key Vault - Shared Type Definitions
 */

// =============================================================================
// Key Types
// =============================================================================

export type KeyType = 'ed25519' | 'secp256k1';

export interface StoredKey {
  id: string;                         // UUID
  name: string;                       // User-assigned label
  type: KeyType;
  publicKey: string;                  // Hex encoded
  privateKey: string;                 // Hex encoded (encrypted in vault)
  createdAt: number;                  // Unix timestamp
  lastUsedAt?: number;                // Unix timestamp
  derivationPath?: string;            // BIP-44 path if derived from mnemonic
  metadata: KeyMetadata;
}

export interface KeyMetadata {
  accumulateUrl?: string;             // acc://... for ED25519 lite accounts
  keyPageUrl?: string;                // acc://adi.acme/book/1 for keypages
  evmAddress?: string;                // 0x... for secp256k1 keys
  mnemonic?: boolean;                 // true if derived from mnemonic
}

// =============================================================================
// Vault Types
// =============================================================================

export interface EncryptedVaultData {
  version: number;                    // Schema version for migrations
  salt: string;                       // Base64 encoded salt for KDF
  iv: string;                         // Base64 encoded IV for AES-GCM
  encryptedPayload: string;           // Base64 encoded encrypted JSON
  kdfParams: KdfParams;
}

export interface KdfParams {
  algorithm: 'pbkdf2';
  iterations: number;                 // 600000 recommended
}

export interface VaultPayload {
  keys: StoredKey[];
  metadata: VaultMetadata;
  mnemonic?: string;                  // Encrypted master mnemonic (optional)
}

export interface VaultMetadata {
  createdAt: number;
  lastModified: number;
  keyCount: number;
}

// =============================================================================
// Sign Request Types
// =============================================================================

export type SignRequestType =
  | 'acc_signTransaction'
  | 'acc_signHash'
  | 'eth_signHash'
  | 'eth_signTypedData'
  | 'certen_signIntent';

export type SignRequestStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'completed'
  | 'error';

export interface SignRequest {
  id: string;                         // UUID for tracking
  type: SignRequestType;
  origin: string;                     // Requesting website origin
  timestamp: number;
  data: SignRequestData;
  status: SignRequestStatus;
}

export type SignRequestData =
  | AccSignTransactionData
  | AccSignHashData
  | EthSignHashData
  | CertenIntentData;

export interface AccSignTransactionData {
  kind: 'acc_transaction';
  principal: string;                  // acc://... URL
  signerUrl: string;                  // Key page or lite account URL
  signerVersion?: number;             // Key page version
  transactionHash: string;            // Hex-encoded hash to sign
  transactionType?: string;           // Human-readable type
  humanReadable?: HumanReadableTransaction;
}

export interface AccSignHashData {
  kind: 'acc_hash';
  hash: string;                       // Hex-encoded hash
  signerUrl?: string;
  humanReadable?: HumanReadableTransaction;
}

export interface EthSignHashData {
  kind: 'eth_hash';
  hash: string;                       // 0x-prefixed hex hash
  address: string;                    // Ethereum address
  humanReadable?: HumanReadableTransaction;
}

export interface CertenIntentData {
  kind: 'certen_intent';
  intentId: string;
  adiUrl: string;
  actionType: string;
  description: string;
  targetChain?: string;
  targetAddress?: string;
  amount?: string;
}

export interface HumanReadableTransaction {
  action: string;                     // "Send Tokens", "Create ADI", etc.
  from?: string;
  to?: string;
  amount?: string;
  memo?: string;
}

// =============================================================================
// Message Types (Content Script <-> Background)
// =============================================================================

export type MessageType =
  | 'CERTEN_RPC_REQUEST'
  | 'CERTEN_RPC_RESPONSE'
  | 'VAULT_UNLOCK'
  | 'VAULT_LOCK'
  | 'VAULT_STATUS'
  | 'GET_KEYS'
  | 'ADD_KEY'
  | 'REMOVE_KEY'
  | 'GET_PENDING_SIGN_REQUEST'
  | 'APPROVE_SIGN_REQUEST'
  | 'REJECT_SIGN_REQUEST';

export interface Message {
  type: MessageType;
  id?: string;
  [key: string]: unknown;
}

export interface RPCRequest extends Message {
  type: 'CERTEN_RPC_REQUEST';
  method: string;
  params: unknown[];
  origin: string;
}

export interface RPCResponse {
  id: string;
  result?: unknown;
  error?: { code: number; message: string };
}

// =============================================================================
// Provider Types (window.certen)
// =============================================================================

export interface CertenAccount {
  url: string;                        // acc://... or 0x...
  type: 'lite' | 'adi' | 'evm';
  publicKey: string;
  name?: string;
}

export interface CertenProvider {
  isCerten: boolean;
  isAccumulate: boolean;
  version: string;

  connect(): Promise<{ accounts: CertenAccount[]; connected: boolean }>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
  getAccounts(): CertenAccount[];
  getNetwork(): 'mainnet' | 'testnet' | 'devnet';

  request(args: { method: string; params?: unknown[] }): Promise<unknown>;

  signTransaction(txData: {
    principal: string;
    signer?: string;
    body: unknown;
    transactionHash?: string;
  }): Promise<{ signature: string; publicKey: string }>;

  signTransactionIntent(intentData: {
    adiUrl: string;
    transaction: unknown;
    signer: string;
    actionType?: string;
    description?: string;
  }): Promise<{ signature: string; publicKey: string }>;

  sendTokens(from: string, to: string, amount: string): Promise<{ hash: string; status: string }>;
  addCredits(from: string, to: string, amount: number, oracle?: number): Promise<{ hash: string }>;

  queryAccount(url: string): Promise<unknown>;
  getBalance(accountUrl: string): Promise<string>;
  getCredits(accountUrl: string): Promise<number>;

  bridgeToEVM(params: {
    sourceAccount: string;
    targetChain: string;
    targetAddress: string;
    amount: string;
  }): Promise<{ bridgeId: string }>;
  getBridgeStatus(bridgeId: string): Promise<{ status: string }>;

  on(eventName: string, handler: (data: unknown) => void): void;
  off(eventName: string, handler: (data: unknown) => void): void;
}

// =============================================================================
// Utility Types
// =============================================================================

export interface SignatureResult {
  signature: string;                  // Hex encoded signature
  publicKey: string;                  // Hex encoded public key
  keyId: string;                      // Key ID used for signing
}
