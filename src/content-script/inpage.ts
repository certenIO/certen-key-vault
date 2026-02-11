/**
 * Certen Key Vault - Inpage Provider Script
 *
 * This script is injected into web pages to provide the window.certen API.
 * It communicates with the content script via window.postMessage.
 */

interface CertenAccount {
  url: string;
  type: 'lite' | 'adi' | 'evm';
  publicKey: string;
  name?: string;
}

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
}

// Request tracking
const pendingRequests = new Map<string, PendingRequest>();
let requestCounter = 0;

// Provider state
let isConnected = false;
let accounts: CertenAccount[] = [];
let currentNetwork: 'mainnet' | 'testnet' | 'devnet' = 'testnet';

// Event handlers
const eventHandlers = new Map<string, Set<(data: unknown) => void>>();

/**
 * Generates a unique request ID.
 */
function generateRequestId(): string {
  return `certen_${Date.now()}_${++requestCounter}`;
}

/**
 * Sends a request to the content script and waits for response.
 */
function sendRequest(method: string, params: unknown[] = []): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const id = generateRequestId();
    pendingRequests.set(id, { resolve, reject });

    window.postMessage({
      type: 'CERTEN_REQUEST',
      id,
      method,
      params
    }, '*');

    // Timeout after 5 minutes
    setTimeout(() => {
      if (pendingRequests.has(id)) {
        pendingRequests.delete(id);
        reject(new Error('Request timeout'));
      }
    }, 300000);
  });
}

/**
 * Emits an event to registered handlers.
 */
function emitEvent(eventName: string, data: unknown): void {
  const handlers = eventHandlers.get(eventName);
  if (handlers) {
    handlers.forEach(handler => {
      try {
        handler(data);
      } catch (e) {
        console.error('[Certen] Event handler error:', e);
      }
    });
  }
}

// =============================================================================
// window.certen Provider
// =============================================================================

const certenProvider = {
  // Identity
  isCerten: true,
  isAccumulate: true,
  version: '1.0.0',

  // ==========================================================================
  // Connection Management
  // ==========================================================================

  async connect(): Promise<{ accounts: CertenAccount[]; connected: boolean }> {
    try {
      const result = await sendRequest('acc_requestAccounts') as {
        accounts: CertenAccount[];
        network: string;
      };
      accounts = result.accounts || [];
      currentNetwork = (result.network as 'mainnet' | 'testnet' | 'devnet') || 'testnet';
      isConnected = accounts.length > 0;
      return { accounts, connected: isConnected };
    } catch (error) {
      isConnected = false;
      accounts = [];
      throw error;
    }
  },

  async disconnect(): Promise<void> {
    await sendRequest('acc_disconnect');
    isConnected = false;
    accounts = [];
    emitEvent('disconnect', {});
  },

  isConnected(): boolean {
    return isConnected;
  },

  getAccounts(): CertenAccount[] {
    return [...accounts];
  },

  getNetwork(): 'mainnet' | 'testnet' | 'devnet' {
    return currentNetwork;
  },

  // ==========================================================================
  // Generic RPC
  // ==========================================================================

  async request(args: { method: string; params?: unknown[] }): Promise<unknown> {
    return sendRequest(args.method, args.params || []);
  },

  // ==========================================================================
  // Signing Methods
  // ==========================================================================

  async signTransaction(txData: {
    principal: string;
    signer?: string;
    body?: unknown;
    transactionHash?: string;
    humanReadable?: {
      action: string;
      from?: string;
      to?: string;
      amount?: string;
      memo?: string;
    };
  }): Promise<{ signature: string; publicKey: string }> {
    return sendRequest('acc_signTransaction', [txData]) as Promise<{
      signature: string;
      publicKey: string;
    }>;
  },

  async signTransactionIntent(intentData: {
    adiUrl: string;
    transaction: unknown;
    signer: string;
    actionType?: string;
    description?: string;
  }): Promise<{ signature: string; publicKey: string }> {
    return sendRequest('certen_signIntent', [intentData]) as Promise<{
      signature: string;
      publicKey: string;
    }>;
  },

  async signHash(hashData: {
    hash: string;
    address?: string;
    keyType?: 'ed25519' | 'secp256k1';
  }): Promise<{ signature: string; publicKey: string }> {
    const method = hashData.keyType === 'secp256k1' ? 'eth_signHash' : 'acc_signHash';
    return sendRequest(method, [hashData]) as Promise<{
      signature: string;
      publicKey: string;
    }>;
  },

  /**
   * Signs a pending transaction for multi-sig approval.
   *
   * @param params.transactionHash - The 64-char hex transaction hash (for display)
   * @param params.dataForSignature - The complete hash to sign (computed by api-bridge)
   * @param params.signer - The key page URL (e.g., acc://adi.acme/book/1)
   * @param params.signerVersion - Key page version (default: 1)
   * @param params.timestamp - Microseconds timestamp (must match api-bridge)
   * @param params.delegators - Optional delegation chain
   * @param params.humanReadable - Human-readable description for the approval popup
   * @returns The signature, public key, and timestamp used during signing
   */
  async signPendingTransaction(params: {
    transactionHash: string;
    dataForSignature?: string;
    signer: string;
    signerVersion?: number;
    timestamp?: number;
    delegators?: string[];
    humanReadable?: {
      action: string;
      from?: string;
      to?: string;
      description?: string;
      [key: string]: unknown;
    };
  }): Promise<{ signature: string; publicKey: string; timestamp?: number }> {
    return sendRequest('acc_signPendingTransaction', [params]) as Promise<{
      signature: string;
      publicKey: string;
      timestamp?: number;
    }>;
  },

  /**
   * Signs a personal message using EIP-191 (personal_sign).
   * This is used for off-chain signature verification.
   *
   * @param message - The message to sign (will be prefixed with EIP-191 header)
   * @param address - The EVM address that should sign (must match a secp256k1 key)
   * @returns The signature and public key
   */
  async signPersonalMessage(
    message: string,
    address: string
  ): Promise<{ signature: string; publicKey: string }> {
    return sendRequest('eth_signPersonalMessage', [{
      message,
      address,
      humanReadable: {
        action: 'Sign Personal Message',
        memo: message.slice(0, 100) + (message.length > 100 ? '...' : '')
      }
    }]) as Promise<{
      signature: string;
      publicKey: string;
    }>;
  },

  // ==========================================================================
  // Key Selection
  // ==========================================================================

  /**
   * Opens a popup for the user to select which key to use.
   * Returns the selected key's public key and SHA-256 hash.
   *
   * @param params.keyType - Filter keys by type (optional)
   * @param params.purpose - Description shown to user (optional)
   * @returns Selected key info including publicKey and publicKeyHash (SHA-256)
   */
  async selectKey(params?: {
    keyType?: 'ed25519' | 'secp256k1' | 'bls12381';
    purpose?: string;
  }): Promise<{
    publicKey: string;
    publicKeyHash: string;
    keyId: string;
    keyName: string;
    keyType: 'ed25519' | 'secp256k1' | 'bls12381';
    accumulateUrl?: string;
    evmAddress?: string;
  }> {
    return sendRequest('acc_selectKey', [params || {}]) as Promise<{
      publicKey: string;
      publicKeyHash: string;
      keyId: string;
      keyName: string;
      keyType: 'ed25519' | 'secp256k1' | 'bls12381';
      accumulateUrl?: string;
      evmAddress?: string;
    }>;
  },

  // ==========================================================================
  // Key Metadata Management
  // ==========================================================================

  /**
   * Updates metadata for a key in the vault.
   * Can identify the key by either publicKey or keyId.
   *
   * @param params.publicKey - The public key (hex) to identify the key
   * @param params.keyId - Alternative: the key's internal ID
   * @param params.metadata - Metadata to update (merged with existing)
   * @returns Success status and keyId
   */
  async updateKeyMetadata(params: {
    publicKey?: string;
    keyId?: string;
    metadata: {
      keyPageUrl?: string;
      [key: string]: unknown;
    };
  }): Promise<{ success: boolean; keyId?: string }> {
    return sendRequest('acc_updateKeyMetadata', [params]) as Promise<{
      success: boolean;
      keyId?: string;
    }>;
  },

  // ==========================================================================
  // Token Operations
  // ==========================================================================

  async sendTokens(
    from: string,
    to: string,
    amount: string
  ): Promise<{ hash: string; status: string }> {
    return sendRequest('acc_sendTokens', [{ from, to, amount }]) as Promise<{
      hash: string;
      status: string;
    }>;
  },

  async addCredits(
    from: string,
    to: string,
    amount: number,
    oracle?: number
  ): Promise<{ hash: string }> {
    return sendRequest('acc_addCredits', [{ from, to, amount, oracle }]) as Promise<{
      hash: string;
    }>;
  },

  // ==========================================================================
  // Query Methods
  // ==========================================================================

  async queryAccount(url: string): Promise<unknown> {
    return sendRequest('acc_queryAccount', [url]);
  },

  async getBalance(accountUrl: string): Promise<string> {
    return sendRequest('acc_getBalance', [accountUrl]) as Promise<string>;
  },

  async getCredits(accountUrl: string): Promise<number> {
    return sendRequest('acc_getCredits', [accountUrl]) as Promise<number>;
  },

  // ==========================================================================
  // Bridge Operations
  // ==========================================================================

  async bridgeToEVM(params: {
    sourceAccount: string;
    targetChain: string;
    targetAddress: string;
    amount: string;
  }): Promise<{ bridgeId: string }> {
    return sendRequest('certen_bridgeToEVM', [params]) as Promise<{ bridgeId: string }>;
  },

  async getBridgeStatus(bridgeId: string): Promise<{ status: string }> {
    return sendRequest('certen_getBridgeStatus', [bridgeId]) as Promise<{ status: string }>;
  },

  // ==========================================================================
  // Event Handling
  // ==========================================================================

  on(eventName: string, handler: (data: unknown) => void): void {
    if (!eventHandlers.has(eventName)) {
      eventHandlers.set(eventName, new Set());
    }
    eventHandlers.get(eventName)!.add(handler);
  },

  off(eventName: string, handler: (data: unknown) => void): void {
    const handlers = eventHandlers.get(eventName);
    if (handlers) {
      handlers.delete(handler);
    }
  }
};

// =============================================================================
// Message Handling
// =============================================================================

// Listen for responses from content script
window.addEventListener('message', (event) => {
  if (event.source !== window) return;

  const { type, id, result, error, event: eventType, data } = event.data || {};

  // Handle RPC responses
  if (type === 'CERTEN_RESPONSE' && id) {
    const pending = pendingRequests.get(id);
    if (pending) {
      pendingRequests.delete(id);
      if (error) {
        pending.reject(new Error(error.message || 'Unknown error'));
      } else {
        pending.resolve(result);
      }
    }
  }

  // Handle events from extension
  if (type === 'CERTEN_EVENT' && eventType) {
    // Update internal state for specific events
    if (eventType === 'accountsChanged') {
      accounts = data?.accounts || [];
      isConnected = accounts.length > 0;
    } else if (eventType === 'networkChanged') {
      currentNetwork = data?.network || 'testnet';
    } else if (eventType === 'disconnect') {
      isConnected = false;
      accounts = [];
    }

    emitEvent(eventType, data);
  }
});

// =============================================================================
// Inject Provider
// =============================================================================

// Freeze the provider to prevent modification
Object.freeze(certenProvider);

// Inject into window
(window as any).certen = certenProvider;

// Also expose as accumulate for compatibility
(window as any).accumulate = certenProvider;

// Announce provider is ready
window.dispatchEvent(new CustomEvent('certen#initialized'));

console.log('[Certen Key Vault] Provider initialized v1.0.0');
