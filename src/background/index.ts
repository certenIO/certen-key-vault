/**
 * Certen Key Vault - Background Service Worker
 *
 * Main entry point for the extension's background script.
 * Handles:
 * - Message routing from content scripts and popup
 * - Vault session management
 * - Auto-lock timer
 * - Badge updates
 */

import { messageRouter } from './messageRouter';
import { keyStore } from '../vault/keyStore';
import { signRequestQueue } from './signRequestQueue';

// =============================================================================
// Message Handler
// =============================================================================

/**
 * Main message listener for all extension communication.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Handle message asynchronously
  messageRouter.handleMessage(message, sender)
    .then(response => {
      sendResponse(response);
    })
    .catch(error => {
      console.error('[Background] Message handling error:', error);
      sendResponse({
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Internal error'
        }
      });
    });

  // Return true to indicate async response
  return true;
});

// =============================================================================
// Extension Icon Click Handler
// =============================================================================

chrome.action.onClicked.addListener(async () => {
  // This is called when user clicks the extension icon
  // Default behavior is to open popup, which is handled by manifest
});

// =============================================================================
// Auto-Lock Timer
// =============================================================================

// Check vault status every minute
chrome.alarms.create('checkAutoLock', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'checkAutoLock') {
    // isUnlocked() internally handles auto-lock timeout
    const isUnlocked = keyStore.isUnlocked();

    // Update badge based on status
    updateBadge(isUnlocked);
  }
});

// Cleanup old sign requests every 5 minutes
chrome.alarms.create('cleanupRequests', { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanupRequests') {
    signRequestQueue.cleanup();
  }
});

// =============================================================================
// Badge Management
// =============================================================================

/**
 * Updates the extension badge based on vault status.
 */
function updateBadge(isUnlocked: boolean): void {
  const pendingCount = signRequestQueue.getPendingCount();

  if (pendingCount > 0) {
    // Show pending count
    chrome.action.setBadgeText({ text: pendingCount.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#FF6B6B' });
  } else if (isUnlocked) {
    // Show unlocked indicator
    chrome.action.setBadgeText({ text: '' });
  } else {
    // Show locked indicator
    chrome.action.setBadgeText({ text: '' });
    chrome.action.setBadgeBackgroundColor({ color: '#888888' });
  }
}

// =============================================================================
// Installation Handler
// =============================================================================

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[Certen Key Vault] Extension installed');

    // Open setup page on first install
    chrome.tabs.create({
      url: chrome.runtime.getURL('popup.html?mode=setup&fullpage=true')
    });
  } else if (details.reason === 'update') {
    console.log('[Certen Key Vault] Extension updated to version', chrome.runtime.getManifest().version);
  }
});

// =============================================================================
// Startup Handler
// =============================================================================

chrome.runtime.onStartup.addListener(() => {
  console.log('[Certen Key Vault] Browser started');
  // Vault is locked by default on browser start
  updateBadge(false);
});

// =============================================================================
// Context Menu (Optional)
// =============================================================================

// Could add right-click context menu for quick actions
// chrome.contextMenus.create({...});

// =============================================================================
// Initial Setup
// =============================================================================

console.log('[Certen Key Vault] Background service worker initialized');

// Update badge on load
keyStore.isInitialized().then(async (initialized) => {
  if (initialized) {
    updateBadge(keyStore.isUnlocked());
  } else {
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#FFA500' });
  }
});
