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
import {
  SignRequest,
  SignRequestData,
  AccSignTransactionData,
  AccSignHashData,
  EthSignHashData,
  CertenIntentData,
  CertenAccount,
  SignatureResult
} from '../shared/types';

// =============================================================================
// Constants
// =============================================================================

// Methods that require signature approval (opens popup)
const SIGN_METHODS = new Set([
  'acc_signTransaction',
  'acc_signHash',
  'eth_signHash',
  'eth_signTypedData',
  'certen_signIntent'
]);

// Methods that require connection
const CONNECTION_REQUIRED_METHODS = new Set([
  ...SIGN_METHODS,
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
let currentNetwork: 'mainnet' | 'testnet' | 'devnet' = 'devnet';

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

        case 'REMOVE_KEY':
          return this.removeKey(message.keyId);

        // Sign request operations
        case 'GET_PENDING_SIGN_REQUEST':
          return this.getPendingSignRequest();

        case 'APPROVE_SIGN_REQUEST':
          return this.approveSignRequest(message.requestId, message.keyId);

        case 'REJECT_SIGN_REQUEST':
          return this.rejectSignRequest(message.requestId, message.reason);

        // Settings
        case 'GET_NETWORK':
          return { network: currentNetwork };

        case 'SET_NETWORK':
          currentNetwork = message.network;
          return { success: true };

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
        case 'acc_signHash':
        case 'eth_signHash':
        case 'certen_signIntent':
          return this.handleSignRequest(method, params[0], origin);

        // Query (no approval needed)
        case 'acc_queryAccount':
        case 'acc_getBalance':
        case 'acc_getCredits':
          // These would typically call the Accumulate bridge
          // For now, return not implemented
          return { error: { code: -32601, message: 'Method not implemented in vault' } };

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

      case 'acc_signHash':
        signData = {
          kind: 'acc_hash',
          hash: data.hash || '',
          signerUrl: data.signerUrl,
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
    } else if (request.data.kind === 'eth_hash') {
      const data = request.data as EthSignHashData;
      if (data.address) {
        const key = this.keyStore.findKeyByEvmAddress(data.address);
        suggestedKeyId = key?.id;
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

      // Get the hash to sign
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
      } else {
        throw new Error('Unknown request type');
      }

      // Sign based on key type
      if (key.type === 'ed25519') {
        signature = signED25519Hex(hash, key.privateKey);
      } else if (key.type === 'secp256k1') {
        signature = await signSecp256k1Hex(hash, key.privateKey);
      } else {
        throw new Error(`Unsupported key type: ${key.type}`);
      }

      const result: SignatureResult = {
        signature,
        publicKey: key.publicKey,
        keyId: key.id
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
      ? this.keyStore.getKeysByType(type as 'ed25519' | 'secp256k1')
      : this.keyStore.getAllKeys();

    return { keys };
  }

  private async generateKey(keyType: string, name: string): Promise<any> {
    try {
      const key = await this.keyStore.generateKey(keyType as 'ed25519' | 'secp256k1', name);
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
      const key = await this.keyStore.deriveKeyFromMnemonic(keyType as 'ed25519' | 'secp256k1', name);
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
      const key = await this.keyStore.importKey(keyType as 'ed25519' | 'secp256k1', privateKey, name);
      return { success: true, key };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Key import failed'
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

  // ===========================================================================
  // Popup Management
  // ===========================================================================

  private async openPopup(mode: 'setup' | 'unlock' | 'approve' | 'default' = 'default'): Promise<void> {
    const url = chrome.runtime.getURL(`popup.html?mode=${mode}`);

    try {
      // Try to use action popup first
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
