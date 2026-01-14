/**
 * Certen Key Vault - Content Script
 *
 * This content script:
 * 1. Injects the inpage provider script into web pages
 * 2. Relays messages between the page and background service worker
 */

// =============================================================================
// Inject Inpage Script
// =============================================================================

/**
 * Injects the inpage script into the page context.
 */
function injectInpageScript(): void {
  try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('inpage.js');
    script.type = 'module';

    // Inject into head or documentElement
    const container = document.head || document.documentElement;
    container.insertBefore(script, container.firstChild);

    // Clean up after injection
    script.addEventListener('load', () => {
      script.remove();
    });

    script.addEventListener('error', (e) => {
      console.error('[Certen Content Script] Failed to inject inpage script:', e);
    });
  } catch (error) {
    console.error('[Certen Content Script] Error injecting inpage script:', error);
  }
}

// Inject immediately
injectInpageScript();

// =============================================================================
// Message Relay: Page <-> Background
// =============================================================================

/**
 * Handles messages from the injected inpage script.
 */
window.addEventListener('message', async (event) => {
  // Only accept messages from the same window
  if (event.source !== window) return;

  const message = event.data;

  // Only handle Certen requests
  if (message?.type !== 'CERTEN_REQUEST') return;

  const { id, method, params } = message;

  try {
    // Forward to background service worker
    const response = await chrome.runtime.sendMessage({
      type: 'CERTEN_RPC_REQUEST',
      id,
      method,
      params,
      origin: window.location.origin
    });

    // Send response back to page
    window.postMessage({
      type: 'CERTEN_RESPONSE',
      id,
      result: response?.result,
      error: response?.error
    }, '*');
  } catch (error) {
    // Send error response
    window.postMessage({
      type: 'CERTEN_RESPONSE',
      id,
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : 'Internal error'
      }
    }, '*');
  }
});

// =============================================================================
// Message Relay: Background -> Page
// =============================================================================

/**
 * Handles messages from the background service worker.
 * Used to broadcast events to the page (e.g., accountsChanged).
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CERTEN_EVENT') {
    // Forward event to page
    window.postMessage({
      type: 'CERTEN_EVENT',
      event: message.event,
      data: message.data
    }, '*');
  }

  // Send empty response to acknowledge
  sendResponse({});
  return false;
});

// =============================================================================
// Connection Status Check
// =============================================================================

/**
 * Periodically checks connection to background service worker.
 */
async function checkConnection(): Promise<boolean> {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'PING' });
    return response?.pong === true;
  } catch {
    return false;
  }
}

// Initial connection check
checkConnection().then(connected => {
  if (!connected) {
    console.warn('[Certen Content Script] Background service worker not available');
  }
});

console.log('[Certen Content Script] Initialized');
