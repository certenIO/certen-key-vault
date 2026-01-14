/**
 * Certen Key Vault - Main App Component
 */

import React, { useState, useEffect } from 'react';
import Setup from './pages/Setup';
import Unlock from './pages/Unlock';
import KeyList from './pages/KeyList';
import SignApproval from './pages/SignApproval';

// =============================================================================
// Types
// =============================================================================

type AppMode = 'loading' | 'setup' | 'unlock' | 'main' | 'approve';

interface VaultStatus {
  isInitialized: boolean;
  isUnlocked: boolean;
  hasMnemonic: boolean;
  keyCount: number;
  network: string;
}

interface AppProps {
  initialMode?: 'setup' | 'unlock' | 'approve' | null;
}

// =============================================================================
// App Component
// =============================================================================

const App: React.FC<AppProps> = ({ initialMode }) => {
  const [mode, setMode] = useState<AppMode>('loading');
  const [vaultStatus, setVaultStatus] = useState<VaultStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load vault status on mount
  useEffect(() => {
    loadVaultStatus();
  }, []);

  // Check for pending sign requests when in main mode
  useEffect(() => {
    if (mode === 'main') {
      checkPendingSignRequests();
    }
  }, [mode]);

  /**
   * Loads vault status from background.
   */
  const loadVaultStatus = async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'VAULT_STATUS' });

      if (response.error) {
        setError(response.error.message);
        return;
      }

      setVaultStatus(response);

      // Determine initial mode
      if (initialMode === 'approve') {
        setMode('approve');
      } else if (!response.isInitialized) {
        setMode('setup');
      } else if (!response.isUnlocked) {
        setMode('unlock');
      } else if (initialMode === 'setup') {
        setMode('main'); // Already initialized
      } else {
        setMode('main');
      }
    } catch (err) {
      setError('Failed to connect to extension');
      console.error('Failed to load vault status:', err);
    }
  };

  /**
   * Checks for pending sign requests.
   */
  const checkPendingSignRequests = async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_PENDING_SIGN_REQUEST' });
      if (response.request) {
        setMode('approve');
      }
    } catch (err) {
      console.error('Failed to check pending requests:', err);
    }
  };

  /**
   * Handles successful vault setup.
   */
  const handleSetupComplete = () => {
    loadVaultStatus();
    setMode('main');
  };

  /**
   * Handles successful vault unlock.
   */
  const handleUnlockSuccess = () => {
    loadVaultStatus();
    checkPendingSignRequests().then(() => {
      if (mode !== 'approve') {
        setMode('main');
      }
    });
  };

  /**
   * Handles vault lock.
   */
  const handleLock = async () => {
    await chrome.runtime.sendMessage({ type: 'VAULT_LOCK' });
    setMode('unlock');
  };

  /**
   * Handles sign request completion.
   */
  const handleSignComplete = () => {
    // Check for more pending requests
    checkPendingSignRequests().then(() => {
      if (mode !== 'approve') {
        setMode('main');
      }
    });
  };

  // ===========================================================================
  // Render
  // ===========================================================================

  if (mode === 'loading') {
    return (
      <div className="app-container">
        <div className="content">
          <div className="loading">
            <div className="spinner" />
            <p className="mt-16">Loading...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="app-container">
        <div className="content">
          <div className="empty-state">
            <div className="empty-state-icon">!</div>
            <p>{error}</p>
            <button className="btn btn-primary mt-16" onClick={loadVaultStatus}>
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  switch (mode) {
    case 'setup':
      return <Setup onComplete={handleSetupComplete} />;

    case 'unlock':
      return <Unlock onUnlock={handleUnlockSuccess} />;

    case 'approve':
      return (
        <SignApproval
          onComplete={handleSignComplete}
          onCancel={() => setMode('main')}
        />
      );

    case 'main':
    default:
      return (
        <KeyList
          vaultStatus={vaultStatus!}
          onLock={handleLock}
          onRefresh={loadVaultStatus}
        />
      );
  }
};

export default App;
