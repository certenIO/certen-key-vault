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
let currentNetwork: 'mainnet' | 'testnet' | 'devnet' = 'devnet';

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
      currentNetwork = (result.network as 'mainnet' | 'testnet' | 'devnet') || 'devnet';
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
      currentNetwork = data?.network || 'devnet';
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
