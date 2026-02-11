/**
 * Certen Key Vault - Message Router
 *
 * Handles all messages from content scripts and popup.
 * Routes RPC requests, manages signing operations, and coordinates with vault.
 */

import { KeyStore, keyStore } from '../vault/keyStore';
import { SignRequestQueue, signRequestQueue } from './signRequestQueue';
import { signED25519, signED25519Hex, fromHex, toHex } from '../vault';
import { signSecp256k1, signSecp256k1Hex } from '../vault/secp256k1';
import { signBLS12381Hex } from '../vault/bls12381';
import {
  SignRequest,
  SignRequestData,
  AccSignTransactionData,
  AccSignPendingTransactionData,
  AccSignHashData,
  EthSignHashData,
  EthSignPersonalMessageData,
  CertenIntentData,
  BlsSignHashData,
  CertenAccount,
  SignatureResult
} from '../shared/types';
import { signEthPersonalMessage } from '../vault/secp256k1';
import { DEFAULT_NETWORK } from '../shared/constants';
import {
  validateMnemonic,
  deriveED25519FromMnemonic,
  deriveSecp256k1FromMnemonic,
  deriveBLS12381FromMnemonic
} from '../vault/mnemonic';

// =============================================================================
// Constants
// =============================================================================

// Methods that require signature approval (opens popup)
const SIGN_METHODS = new Set([
  'acc_signTransaction',
  'acc_signPendingTransaction',
  'acc_signHash',
  'eth_signHash',
  'eth_signTypedData',
  'eth_signPersonalMessage',
  'certen_signIntent',
  'bls_signHash'
]);

// Methods that require connection
// NOTE: Signing methods are NOT included here because:
// 1. The popup approval dialog is the real security gate
// 2. connectedSites is in-memory and lost when service worker restarts
// 3. Users would get confusing "not connected" errors after browser restart
const CONNECTION_REQUIRED_METHODS = new Set([
  'acc_sendTokens',
  'acc_addCredits',
  'certen_bridgeToEVM'
]);

// =============================================================================
// State
// =============================================================================

// Connected sites
const connectedSites = new Map<string, boolean>();

// Current network
let currentNetwork: 'mainnet' | 'testnet' | 'devnet' = DEFAULT_NETWORK as 'mainnet' | 'testnet' | 'devnet';

// =============================================================================
// Message Router Class
// =============================================================================

export class MessageRouter {
  private keyStore: KeyStore;
  private signQueue: SignRequestQueue;

  constructor(ks: KeyStore = keyStore, sq: SignRequestQueue = signRequestQueue) {
    this.keyStore = ks;
    this.signQueue = sq;
  }

  /**
   * Main message handler.
   */
  async handleMessage(
    message: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    const { type } = message;

    try {
      switch (type) {
        case 'PING':
          return { pong: true };

        case 'CERTEN_RPC_REQUEST':
          return this.handleRPCRequest(message, sender);

        // Vault operations
        case 'VAULT_STATUS':
          return this.getVaultStatus();

        case 'VAULT_INITIALIZE':
          return this.initializeVault(message.password, message.mnemonic);

        case 'VAULT_UNLOCK':
          return this.unlockVault(message.password);

        case 'VAULT_LOCK':
          return this.lockVault();

        case 'VAULT_RESET':
          return this.resetVault();

        // Key operations
        case 'GET_KEYS':
          return this.getKeys(message.keyType);

        case 'GENERATE_KEY':
          return this.generateKey(message.keyType, message.name);

        case 'DERIVE_KEY':
          return this.deriveKey(message.keyType, message.name);

        case 'IMPORT_KEY':
          return this.importKey(message.keyType, message.privateKey, message.name);

        case 'IMPORT_MNEMONIC':
          return this.importFromMnemonic(message.mnemonic, message.keyType, message.name);

        case 'REMOVE_KEY':
          return this.removeKey(message.keyId);

        case 'UPDATE_KEY_METADATA':
          return this.updateKeyMetadata(message.keyId, message.metadata);

        // Sign request operations
        case 'GET_PENDING_SIGN_REQUEST':
          return this.getPendingSignRequest();

        case 'APPROVE_SIGN_REQUEST':
          return this.approveSignRequest(message.requestId, message.keyId);

        case 'REJECT_SIGN_REQUEST':
          return this.rejectSignRequest(message.requestId, message.reason);

        // Key selection operations
        case 'GET_PENDING_KEY_SELECTION':
          return { selection: this.getPendingKeySelection() };

        case 'COMPLETE_KEY_SELECTION':
          return this.completeKeySelection(message.requestId, message.keyId);

        case 'REJECT_KEY_SELECTION':
          return this.rejectKeySelection(message.requestId, message.reason);

        // Settings
        case 'GET_NETWORK':
          return { network: currentNetwork };

        case 'SET_NETWORK':
          currentNetwork = message.network;
          return { success: true };

        // Secret export (for Settings page)
        case 'GET_MNEMONIC':
          return this.getMnemonic();

        case 'GET_KEY_WITH_PRIVATE':
          return this.getKeyWithPrivate(message.keyId);

        default:
          throw new Error(`Unknown message type: ${type}`);
      }
    } catch (error) {
      return {
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Internal error'
        }
      };
    }
  }

  // ===========================================================================
  // RPC Request Handling
  // ===========================================================================

  private async handleRPCRequest(
    message: any,
    sender: chrome.runtime.MessageSender
  ): Promise<any> {
    const { method, params, origin } = message;

    // Check if connection is required
    if (CONNECTION_REQUIRED_METHODS.has(method)) {
      if (!this.isConnected(origin)) {
        return {
          error: { code: 4100, message: 'Not connected. Please call connect() first.' }
        };
      }
    }

    // Check if vault is unlocked for sign methods
    if (SIGN_METHODS.has(method)) {
      if (!this.keyStore.isUnlocked()) {
        // Need to prompt user to unlock
        await this.openPopup('unlock');
        return {
          error: { code: 4100, message: 'Vault is locked. Please unlock first.' }
        };
      }
    }

    try {
      switch (method) {
        // Connection
        case 'acc_requestAccounts':
          return this.handleConnect(origin);

        case 'acc_getAccounts':
          return this.handleGetAccounts();

        case 'acc_disconnect':
          return this.handleDisconnect(origin);

        // Signing (requires popup approval)
        case 'acc_signTransaction':
        case 'acc_signPendingTransaction':
        case 'acc_signHash':
        case 'eth_signHash':
        case 'eth_signPersonalMessage':
        case 'certen_signIntent':
        case 'bls_signHash':
          return this.handleSignRequest(method, params[0], origin);

        // Query (no approval needed)
        case 'acc_queryAccount':
        case 'acc_getBalance':
        case 'acc_getCredits':
          // These would typically call the Accumulate bridge
          // For now, return not implemented
          return { error: { code: -32601, message: 'Method not implemented in vault' } };

        // Key metadata update (no approval needed - site is connected)
        case 'acc_updateKeyMetadata':
          return this.handleUpdateKeyMetadata(params[0] as {
            publicKey?: string;
            keyId?: string;
            metadata: { keyPageUrl?: string; [key: string]: unknown };
          });

        // Key selection (opens popup for user to choose a key)
        case 'acc_selectKey':
          return this.handleSelectKey(params[0] as {
            keyType?: 'ed25519' | 'secp256k1' | 'bls12381';
            purpose?: string;
          }, origin);

        default:
          return { error: { code: -32601, message: `Method not found: ${method}` } };
      }
    } catch (error) {
      return {
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Internal error'
        }
      };
    }
  }

  // ===========================================================================
  // Connection Handling
  // ===========================================================================

  private async handleConnect(origin: string): Promise<any> {
    // Check if vault is initialized
    const isInitialized = await this.keyStore.isInitialized();
    if (!isInitialized) {
      await this.openPopup('setup');
      return { result: { accounts: [], connected: false, needsSetup: true } };
    }

    // Check if vault is unlocked
    if (!this.keyStore.isUnlocked()) {
      await this.openPopup('unlock');
      return { result: { accounts: [], connected: false, needsUnlock: true } };
    }

    // Mark site as connected
    connectedSites.set(origin, true);

    // Get accounts
    const accounts = this.getAccountsForConnection();

    return {
      result: {
        accounts,
        connected: true,
        network: currentNetwork
      }
    };
  }

  private handleGetAccounts(): any {
    if (!this.keyStore.isUnlocked()) {
      return { result: [] };
    }
    return { result: this.getAccountsForConnection() };
  }

  private handleDisconnect(origin: string): any {
    connectedSites.delete(origin);
    return { result: { success: true } };
  }

  private isConnected(origin: string): boolean {
    return connectedSites.get(origin) === true;
  }

  private getAccountsForConnection(): CertenAccount[] {
    const keys = this.keyStore.getAllKeys();
    return keys.map(key => ({
      url: key.metadata.accumulateUrl || key.metadata.evmAddress || '',
      type: key.type === 'ed25519' ? 'lite' as const : 'evm' as const,
      publicKey: key.publicKey,
      name: key.name
    }));
  }

  // ===========================================================================
  // Sign Request Handling
  // ===========================================================================

  private async handleSignRequest(
    method: string,
    data: any,
    origin: string
  ): Promise<any> {
    // Create sign request data based on method
    let signData: SignRequestData;

    switch (method) {
      case 'acc_signTransaction':
        signData = {
          kind: 'acc_transaction',
          principal: data.principal || '',
          signerUrl: data.signer || data.signerUrl || '',
          signerVersion: data.signerVersion,
          transactionHash: data.transactionHash || data.hash || '',
          transactionType: data.transactionType,
          humanReadable: data.humanReadable
        } as AccSignTransactionData;
        break;

      case 'acc_signPendingTransaction':
        signData = {
          kind: 'acc_pending_transaction',
          transactionHash: data.transactionHash || data.hash || '',
          dataForSignature: data.dataForSignature,  // Complete hash to sign
          signerUrl: data.signer || data.signerUrl || '',
          signerVersion: data.signerVersion || 1,
          timestamp: data.timestamp,
          delegators: data.delegators,
          humanReadable: data.humanReadable || {
            action: 'Sign Pending Transaction',
            memo: `Sign pending transaction with ${data.signer || data.signerUrl || 'key'}`
          }
        } as AccSignPendingTransactionData;
        break;

      case 'acc_signHash':
        signData = {
          kind: 'acc_hash',
          hash: data.hash || '',
          signerUrl: data.signerUrl || data.address, // Accept both signerUrl and address
          humanReadable: data.humanReadable
        } as AccSignHashData;
        break;

      case 'eth_signHash':
        signData = {
          kind: 'eth_hash',
          hash: data.hash || '',
          address: data.address || '',
          humanReadable: data.humanReadable
        } as EthSignHashData;
        break;

      case 'eth_signPersonalMessage':
        signData = {
          kind: 'eth_personal_message',
          message: data.message || '',
          address: data.address || '',
          humanReadable: data.humanReadable || {
            action: 'Sign Personal Message',
            memo: data.message?.slice(0, 100) + (data.message?.length > 100 ? '...' : '')
          }
        } as EthSignPersonalMessageData;
        break;

      case 'certen_signIntent':
        signData = {
          kind: 'certen_intent',
          intentId: data.intentId || '',
          adiUrl: data.adiUrl || '',
          actionType: data.actionType || '',
          description: data.description || '',
          targetChain: data.targetChain,
          targetAddress: data.targetAddress,
          amount: data.amount
        } as CertenIntentData;
        break;

      case 'bls_signHash':
        signData = {
          kind: 'bls_hash',
          hash: data.hash || '',
          humanReadable: data.humanReadable
        } as BlsSignHashData;
        break;

      default:
        return { error: { code: -32601, message: `Unknown sign method: ${method}` } };
    }

    // Add to queue
    const requestId = this.signQueue.add(
      method as SignRequest['type'],
      signData,
      origin
    );

    // Open approval popup
    await this.openPopup('approve');

    // Wait for approval/rejection
    return new Promise((resolve) => {
      this.signQueue.onComplete(requestId, (result, error) => {
        if (error) {
          resolve({ error: { code: 4001, message: error } });
        } else {
          resolve({ result });
        }
      });
    });
  }

  // ===========================================================================
  // Sign Request Approval/Rejection
  // ===========================================================================

  private getPendingSignRequest(): any {
    const request = this.signQueue.getNext();
    if (!request) {
      return { request: null };
    }

    // Suggest a key based on the request
    let suggestedKeyId: string | undefined;

    if (request.data.kind === 'acc_transaction' || request.data.kind === 'acc_hash') {
      const data = request.data as AccSignTransactionData | AccSignHashData;
      if (data.signerUrl) {
        const key = this.keyStore.findKeyByAccumulateUrl(data.signerUrl);
        suggestedKeyId = key?.id;
      }
    } else if (request.data.kind === 'acc_pending_transaction') {
      const data = request.data as AccSignPendingTransactionData;
      if (data.signerUrl) {
        // Try to find key by key page URL first (most common case for pending tx signing)
        let key = this.keyStore.findKeyByKeyPageUrl(data.signerUrl);
        if (!key) {
          // Fall back to checking lite account URL
          key = this.keyStore.findKeyByAccumulateUrl(data.signerUrl);
        }
        if (!key) {
          // Try checking any Accumulate URL (both keyPageUrl and accumulateUrl)
          key = this.keyStore.findKeyByAnyAccumulateUrl(data.signerUrl);
        }
        suggestedKeyId = key?.id;
      }
      // If no key found by URL, suggest first ED25519 key
      if (!suggestedKeyId) {
        const ed25519Keys = this.keyStore.getKeysByType('ed25519');
        if (ed25519Keys.length > 0) {
          suggestedKeyId = ed25519Keys[0].id;
        }
      }
    } else if (request.data.kind === 'eth_hash') {
      const data = request.data as EthSignHashData;
      if (data.address) {
        const key = this.keyStore.findKeyByEvmAddress(data.address);
        suggestedKeyId = key?.id;
      }
    } else if (request.data.kind === 'eth_personal_message') {
      const data = request.data as EthSignPersonalMessageData;
      if (data.address) {
        const key = this.keyStore.findKeyByEvmAddress(data.address);
        suggestedKeyId = key?.id;
      }
    } else if (request.data.kind === 'bls_hash') {
      // For BLS, try to find a BLS key - just suggest the first one
      const blsKeys = this.keyStore.getKeysByType('bls12381');
      if (blsKeys.length > 0) {
        suggestedKeyId = blsKeys[0].id;
      }
    }

    return { request, suggestedKeyId };
  }

  private async approveSignRequest(requestId: string, keyId: string): Promise<any> {
    if (!this.keyStore.isUnlocked()) {
      return { error: { code: 4100, message: 'Vault is locked' } };
    }

    const request = this.signQueue.get(requestId);
    if (!request) {
      return { error: { code: -32600, message: 'Request not found' } };
    }

    const key = this.keyStore.getKey(keyId);
    if (!key) {
      return { error: { code: -32600, message: 'Key not found' } };
    }

    try {
      let signature: string;
      let timestampUsed: number | undefined;

      // Handle personal message signing separately (EIP-191)
      if (request.data.kind === 'eth_personal_message') {
        const data = request.data as EthSignPersonalMessageData;

        if (key.type !== 'secp256k1') {
          throw new Error('Personal message signing requires a secp256k1 key');
        }

        // Sign using EIP-191 personal_sign
        const privateKeyBytes = fromHex(key.privateKey);
        const signatureBytes = await signEthPersonalMessage(data.message, privateKeyBytes);
        signature = '0x' + toHex(signatureBytes);
      } else if (request.data.kind === 'acc_pending_transaction') {
        // Handle pending transaction signing - compute dataForSignature properly
        const data = request.data as AccSignPendingTransactionData;

        if (key.type !== 'ed25519') {
          throw new Error('Pending transaction signing requires an ED25519 key');
        }

        // Use timestamp from request (should match what api-bridge used)
        const timestamp = data.timestamp || (Date.now() * 1000);
        timestampUsed = timestamp;

        let hashToSign: string;

        if (data.dataForSignature) {
          // If api-bridge provided the complete dataForSignature, use it directly
          // This is the preferred path - api-bridge uses SDK's encode function
          hashToSign = data.dataForSignature;
          console.log('[MessageRouter] Using dataForSignature from api-bridge');
        } else {
          // Fallback: compute dataForSignature locally (may have encoding mismatch)
          console.warn('[MessageRouter] No dataForSignature provided, computing locally (may fail)');
          hashToSign = await this.computeDataForSignature(
            data.transactionHash,
            data.signerUrl,
            data.signerVersion || 1,
            timestamp
          );
        }

        // Sign the hash directly
        signature = signED25519Hex(hashToSign, key.privateKey);

        console.log('[MessageRouter] Signed pending transaction:', {
          txHash: data.transactionHash.substring(0, 16) + '...',
          dataForSignature: hashToSign.substring(0, 16) + '...',
          signerUrl: data.signerUrl,
          timestamp,
          usedApiDataForSignature: !!data.dataForSignature,
          signatureLength: signature.length
        });
      } else {
        // Get the hash to sign for other request types
        let hash: string;
        if (request.data.kind === 'acc_transaction') {
          hash = (request.data as AccSignTransactionData).transactionHash;
        } else if (request.data.kind === 'acc_hash') {
          hash = (request.data as AccSignHashData).hash;
        } else if (request.data.kind === 'eth_hash') {
          hash = (request.data as EthSignHashData).hash;
        } else if (request.data.kind === 'certen_intent') {
          // For intents, we might need to compute a hash from the data
          // For now, use intentId as placeholder
          hash = (request.data as CertenIntentData).intentId;
        } else if (request.data.kind === 'bls_hash') {
          hash = (request.data as BlsSignHashData).hash;
        } else {
          throw new Error('Unknown request type');
        }

        // Sign based on key type
        if (key.type === 'ed25519') {
          signature = signED25519Hex(hash, key.privateKey);
        } else if (key.type === 'secp256k1') {
          signature = await signSecp256k1Hex(hash, key.privateKey);
        } else if (key.type === 'bls12381') {
          signature = signBLS12381Hex(hash, key.privateKey);
        } else {
          throw new Error(`Unsupported key type: ${key.type}`);
        }
      }

      const result: SignatureResult = {
        signature,
        publicKey: key.publicKey,
        keyId: key.id,
        timestamp: timestampUsed
      };

      // Complete the request
      this.signQueue.complete(requestId, result);

      return { success: true, result };
    } catch (error) {
      this.signQueue.error(requestId, error instanceof Error ? error.message : 'Signing failed');
      return {
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Signing failed'
        }
      };
    }
  }

  private rejectSignRequest(requestId: string, reason: string): any {
    this.signQueue.reject(requestId, reason || 'User rejected');
    return { success: true };
  }

  // ===========================================================================
  // Vault Operations
  // ===========================================================================

  private async getVaultStatus(): Promise<any> {
    const isInitialized = await this.keyStore.isInitialized();
    const isUnlocked = this.keyStore.isUnlocked();
    const hasMnemonic = isUnlocked ? this.keyStore.hasMnemonic() : false;
    const keyCount = isUnlocked ? this.keyStore.getAllKeys().length : 0;

    return {
      isInitialized,
      isUnlocked,
      hasMnemonic,
      keyCount,
      network: currentNetwork
    };
  }

  private async initializeVault(password: string, mnemonic?: string): Promise<any> {
    try {
      if (mnemonic) {
        const savedMnemonic = await this.keyStore.initializeWithMnemonic(password, mnemonic);
        return { success: true, mnemonic: savedMnemonic };
      } else {
        const savedMnemonic = await this.keyStore.initializeWithMnemonic(password);
        return { success: true, mnemonic: savedMnemonic };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Initialization failed'
      };
    }
  }

  private async unlockVault(password: string): Promise<any> {
    try {
      await this.keyStore.unlock(password);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unlock failed'
      };
    }
  }

  private lockVault(): any {
    this.keyStore.lock();
    return { success: true };
  }

  private async resetVault(): Promise<any> {
    try {
      await this.keyStore.reset();
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Reset failed'
      };
    }
  }

  // ===========================================================================
  // Key Operations
  // ===========================================================================

  private getKeys(type?: string): any {
    if (!this.keyStore.isUnlocked()) {
      return { error: { message: 'Vault is locked' } };
    }

    const keys = type
      ? this.keyStore.getKeysByType(type as 'ed25519' | 'secp256k1' | 'bls12381')
      : this.keyStore.getAllKeys();

    return { keys };
  }

  private async generateKey(keyType: string, name: string): Promise<any> {
    try {
      const key = await this.keyStore.generateKey(keyType as 'ed25519' | 'secp256k1' | 'bls12381', name);
      return { success: true, key };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Key generation failed'
      };
    }
  }

  private async deriveKey(keyType: string, name: string): Promise<any> {
    console.log('[MessageRouter] deriveKey called:', { keyType, name });
    try {
      const key = await this.keyStore.deriveKeyFromMnemonic(keyType as 'ed25519' | 'secp256k1' | 'bls12381', name);
      console.log('[MessageRouter] Key derived successfully:', key.id);
      return { success: true, key };
    } catch (error) {
      console.error('[MessageRouter] Key derivation failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Key derivation failed'
      };
    }
  }

  private async importKey(keyType: string, privateKey: string, name: string): Promise<any> {
    try {
      const key = await this.keyStore.importKey(keyType as 'ed25519' | 'secp256k1' | 'bls12381', privateKey, name);
      return { success: true, key };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Key import failed'
      };
    }
  }

  private async importFromMnemonic(mnemonic: string, keyType: string, name: string): Promise<any> {
    try {
      // Validate mnemonic
      if (!validateMnemonic(mnemonic)) {
        return { success: false, error: 'Invalid mnemonic phrase. Please enter a valid 12 or 24 word BIP-39 mnemonic.' };
      }

      // Derive key from mnemonic
      let privateKeyHex: string;

      if (keyType === 'ed25519') {
        const derived = deriveED25519FromMnemonic(mnemonic, 0);
        // ED25519 private key is 64 bytes (seed + public key), but we store just the 32-byte seed
        privateKeyHex = toHex(derived.seed);
      } else if (keyType === 'secp256k1') {
        const derived = deriveSecp256k1FromMnemonic(mnemonic, 0);
        privateKeyHex = toHex(derived.privateKey);
      } else if (keyType === 'bls12381') {
        const derived = deriveBLS12381FromMnemonic(mnemonic, 0);
        privateKeyHex = toHex(derived.privateKey);
      } else {
        return { success: false, error: `Unsupported key type: ${keyType}` };
      }

      // Import the derived key
      const key = await this.keyStore.importKey(keyType as 'ed25519' | 'secp256k1' | 'bls12381', privateKeyHex, name);
      return { success: true, key };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Mnemonic import failed'
      };
    }
  }

  private async removeKey(keyId: string): Promise<any> {
    try {
      await this.keyStore.removeKey(keyId);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Key removal failed'
      };
    }
  }

  private async updateKeyMetadata(
    keyId: string,
    metadata: { keyPageUrl?: string; [key: string]: unknown }
  ): Promise<any> {
    try {
      await this.keyStore.updateKey(keyId, { metadata });
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Metadata update failed'
      };
    }
  }

  /**
   * Handles RPC request to update key metadata.
   * Can find key by publicKey or keyId.
   */
  private async handleUpdateKeyMetadata(params: {
    publicKey?: string;
    keyId?: string;
    metadata: { keyPageUrl?: string; [key: string]: unknown };
  }): Promise<any> {
    if (!this.keyStore.isUnlocked()) {
      return { error: { code: 4100, message: 'Vault is locked' } };
    }

    try {
      let keyId = params.keyId;

      // If no keyId provided, find by public key
      if (!keyId && params.publicKey) {
        const keys = this.keyStore.getAllKeys();
        const key = keys.find(k => k.publicKey.toLowerCase() === params.publicKey!.toLowerCase());
        if (!key) {
          return { error: { code: -32600, message: 'Key not found for given public key' } };
        }
        keyId = key.id;
      }

      if (!keyId) {
        return { error: { code: -32600, message: 'Must provide keyId or publicKey' } };
      }

      await this.keyStore.updateKey(keyId, { metadata: params.metadata });
      return { result: { success: true, keyId } };
    } catch (error) {
      return {
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Metadata update failed'
        }
      };
    }
  }

  // ===========================================================================
  // Secret Export (for Settings page)
  // ===========================================================================

  private getMnemonic(): any {
    if (!this.keyStore.isUnlocked()) {
      return { error: { message: 'Vault is locked' } };
    }

    const mnemonic = this.keyStore.getMnemonic();
    if (!mnemonic) {
      return { error: { message: 'No mnemonic stored in vault' } };
    }

    return { mnemonic };
  }

  private getKeyWithPrivate(keyId: string): any {
    if (!this.keyStore.isUnlocked()) {
      return { error: { message: 'Vault is locked' } };
    }

    const key = this.keyStore.getKey(keyId);
    if (!key) {
      return { error: { message: 'Key not found' } };
    }

    return { key };
  }

  // ===========================================================================
  // Key Selection Handling
  // ===========================================================================

  // Pending key selection requests
  private pendingKeySelections = new Map<string, {
    keyType?: 'ed25519' | 'secp256k1' | 'bls12381';
    purpose?: string;
    origin: string;
    resolve: (result: any) => void;
    reject: (error: any) => void;
  }>();

  private async handleSelectKey(
    params: { keyType?: 'ed25519' | 'secp256k1' | 'bls12381'; purpose?: string },
    origin: string
  ): Promise<any> {
    // Check if vault is initialized and unlocked
    if (!await this.keyStore.isInitialized()) {
      await this.openPopup('setup');
      return { error: { code: 4100, message: 'Vault not initialized' } };
    }

    if (!this.keyStore.isUnlocked()) {
      await this.openPopup('unlock');
      return { error: { code: 4100, message: 'Vault is locked. Please unlock first.' } };
    }

    // Get available keys
    const allKeys = params.keyType
      ? this.keyStore.getKeysByType(params.keyType)
      : this.keyStore.getAllKeys();

    if (allKeys.length === 0) {
      return { error: { code: -32600, message: 'No keys available in vault' } };
    }

    // Create request ID
    const requestId = `select_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Wait for user selection - add to pending BEFORE opening popup to avoid race condition
    return new Promise((resolve, reject) => {
      // Add to pending selections first
      this.pendingKeySelections.set(requestId, {
        ...params,
        origin,
        resolve,
        reject
      });

      // Then open popup for user to select key
      this.openPopup('select').catch(err => {
        console.error('[MessageRouter] Failed to open key selection popup:', err);
        this.pendingKeySelections.delete(requestId);
        resolve({ error: { code: -32603, message: 'Failed to open key selection popup' } });
      });

      // Timeout after 5 minutes
      setTimeout(() => {
        if (this.pendingKeySelections.has(requestId)) {
          this.pendingKeySelections.delete(requestId);
          resolve({ error: { code: 4001, message: 'Key selection timeout' } });
        }
      }, 300000);
    });
  }

  getPendingKeySelection(): { requestId: string; keyType?: string; purpose?: string; origin: string } | null {
    const entry = this.pendingKeySelections.entries().next().value;
    if (entry) {
      const [requestId, data] = entry;
      return { requestId, keyType: data.keyType, purpose: data.purpose, origin: data.origin };
    }
    return null;
  }

  async completeKeySelection(requestId: string, keyId: string): Promise<any> {
    const pending = this.pendingKeySelections.get(requestId);
    if (!pending) {
      return { error: { code: -32600, message: 'Selection request not found' } };
    }

    if (!this.keyStore.isUnlocked()) {
      return { error: { code: 4100, message: 'Vault is locked' } };
    }

    const key = this.keyStore.getKey(keyId);
    if (!key) {
      return { error: { code: -32600, message: 'Key not found' } };
    }

    // Compute SHA-256 hash of public key
    const publicKeyHash = await this.computePublicKeyHash(key.publicKey);

    const result = {
      publicKey: key.publicKey,
      publicKeyHash,
      keyId: key.id,
      keyName: key.name,
      keyType: key.type,
      accumulateUrl: key.metadata.accumulateUrl,
      evmAddress: key.metadata.evmAddress
    };

    this.pendingKeySelections.delete(requestId);
    pending.resolve({ result });

    return { success: true, result };
  }

  rejectKeySelection(requestId: string, reason: string): any {
    const pending = this.pendingKeySelections.get(requestId);
    if (!pending) {
      return { error: { code: -32600, message: 'Selection request not found' } };
    }

    this.pendingKeySelections.delete(requestId);
    pending.resolve({ error: { code: 4001, message: reason || 'User rejected key selection' } });

    return { success: true };
  }

  private async computePublicKeyHash(publicKeyHex: string): Promise<string> {
    // Convert hex to bytes
    const publicKeyBytes = new Uint8Array(
      publicKeyHex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
    );

    // Compute SHA-256 using Web Crypto API
    const hashBuffer = await crypto.subtle.digest('SHA-256', publicKeyBytes);
    const hashArray = new Uint8Array(hashBuffer);

    // Convert to hex
    return Array.from(hashArray)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Compute dataForSignature for Accumulate pending transaction signing.
   *
   * According to the Accumulate protocol, the signature is computed over:
   * dataForSignature = SHA256(transactionHash + metadataHash)
   *
   * Where metadataHash = SHA256(signerUrlBytes + signerVersionLE + timestampLE)
   *
   * This is based on how the Accumulate SDK computes tx.dataForSignature(sigInfo)
   *
   * @param transactionHash - 64-char hex string (32 bytes)
   * @param signerUrl - The key page URL (e.g., acc://adi.acme/book/1)
   * @param signerVersion - Key page version (uint64)
   * @param timestamp - Microseconds timestamp (uint64)
   * @returns Hex-encoded dataForSignature hash (64 chars)
   */
  private async computeDataForSignature(
    transactionHash: string,
    signerUrl: string,
    signerVersion: number,
    timestamp: number
  ): Promise<string> {
    // Convert transaction hash from hex to bytes (32 bytes)
    const txHashBytes = new Uint8Array(
      transactionHash.replace(/^0x/, '').match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
    );

    // Encode signer URL as length-prefixed bytes (varint + UTF8)
    const signerUrlBytes = new TextEncoder().encode(signerUrl);
    const signerUrlLengthVarint = this.encodeVarint(signerUrlBytes.length);
    const signerUrlEncoded = new Uint8Array([...signerUrlLengthVarint, ...signerUrlBytes]);

    // Encode signer version as 8-byte little-endian uint64
    const signerVersionBytes = new Uint8Array(8);
    const versionView = new DataView(signerVersionBytes.buffer);
    // JavaScript numbers are doubles, but for version we can safely use BigInt
    versionView.setBigUint64(0, BigInt(signerVersion), true); // true = little endian

    // Encode timestamp as 8-byte little-endian uint64
    const timestampBytes = new Uint8Array(8);
    const timestampView = new DataView(timestampBytes.buffer);
    timestampView.setBigUint64(0, BigInt(timestamp), true); // true = little endian

    // Compute metadataHash = SHA256(signerUrlEncoded + signerVersionBytes + timestampBytes)
    const metadataBytes = new Uint8Array([
      ...signerUrlEncoded,
      ...signerVersionBytes,
      ...timestampBytes
    ]);
    const metadataHashBuffer = await crypto.subtle.digest('SHA-256', metadataBytes);
    const metadataHash = new Uint8Array(metadataHashBuffer);

    // Compute dataForSignature = SHA256(transactionHash + metadataHash)
    const dataForSignatureInput = new Uint8Array([...txHashBytes, ...metadataHash]);
    const dataForSignatureBuffer = await crypto.subtle.digest('SHA-256', dataForSignatureInput);
    const dataForSignatureBytes = new Uint8Array(dataForSignatureBuffer);

    // Convert to hex string
    return Array.from(dataForSignatureBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Encode a number as a varint (variable-length integer).
   * Used for length-prefixed encoding in Accumulate protocol.
   */
  private encodeVarint(value: number): Uint8Array {
    const bytes: number[] = [];
    while (value > 0x7f) {
      bytes.push((value & 0x7f) | 0x80);
      value >>>= 7;
    }
    bytes.push(value);
    return new Uint8Array(bytes);
  }

  // ===========================================================================
  // Popup Management
  // ===========================================================================

  private async openPopup(mode: 'setup' | 'unlock' | 'approve' | 'select' | 'default' = 'default'): Promise<void> {
    const url = chrome.runtime.getURL(`popup.html?mode=${mode}`);

    // For modes that need specific handling, always create a window
    // chrome.action.openPopup() doesn't support passing URL parameters
    if (mode === 'select' || mode === 'approve') {
      await chrome.windows.create({
        url,
        type: 'popup',
        width: 400,
        height: 600,
        focused: true
      });
      return;
    }

    try {
      // Try to use action popup first for other modes
      await chrome.action.openPopup();
    } catch {
      // Fallback to creating a window
      await chrome.windows.create({
        url,
        type: 'popup',
        width: 400,
        height: 600,
        focused: true
      });
    }
  }
}

// =============================================================================
// Singleton Instance
// =============================================================================

export const messageRouter = new MessageRouter();
