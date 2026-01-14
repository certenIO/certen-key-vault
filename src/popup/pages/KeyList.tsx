/**
 * Certen Key Vault - Key List Page
 *
 * Main view showing all keys in the vault.
 */

import React, { useState, useEffect } from 'react';
import { StoredKey } from '../../shared/types';

// =============================================================================
// Types
// =============================================================================

interface KeyListProps {
  vaultStatus: {
    isInitialized: boolean;
    isUnlocked: boolean;
    hasMnemonic: boolean;
    keyCount: number;
    network: string;
  };
  onLock: () => void;
  onRefresh: () => void;
}

// =============================================================================
// KeyList Component
// =============================================================================

const KeyList: React.FC<KeyListProps> = ({ vaultStatus, onLock, onRefresh }) => {
  const [keys, setKeys] = useState<StoredKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddKey, setShowAddKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyType, setNewKeyType] = useState<'ed25519' | 'secp256k1'>('ed25519');
  const [addKeyMode, setAddKeyMode] = useState<'derive' | 'generate' | 'import'>('derive');
  const [importPrivateKey, setImportPrivateKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Load keys on mount
  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = async () => {
    setLoading(true);
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_KEYS' });
      if (response.keys) {
        setKeys(response.keys);
      } else if (response.error?.message === 'Vault is locked' || response.error?.includes?.('locked')) {
        // Vault was locked by service worker restart, refresh status
        console.log('[KeyList] Vault is locked during loadKeys, refreshing...');
        onRefresh();
        return;
      }
    } catch (err) {
      console.error('Failed to load keys:', err);
    }
    setLoading(false);
  };

  const handleAddKey = async () => {
    setError(null);
    setActionLoading(true);

    try {
      let response;

      if (addKeyMode === 'derive') {
        response = await chrome.runtime.sendMessage({
          type: 'DERIVE_KEY',
          keyType: newKeyType,
          name: newKeyName || `${newKeyType === 'ed25519' ? 'Accumulate' : 'Ethereum'} Key`
        });
      } else if (addKeyMode === 'generate') {
        response = await chrome.runtime.sendMessage({
          type: 'GENERATE_KEY',
          keyType: newKeyType,
          name: newKeyName || `${newKeyType === 'ed25519' ? 'Accumulate' : 'Ethereum'} Key`
        });
      } else if (addKeyMode === 'import') {
        response = await chrome.runtime.sendMessage({
          type: 'IMPORT_KEY',
          keyType: newKeyType,
          privateKey: importPrivateKey.trim(),
          name: newKeyName || `Imported ${newKeyType === 'ed25519' ? 'Accumulate' : 'Ethereum'} Key`
        });
      }

      console.log('[KeyList] Response from add key:', response);
      if (response?.success) {
        setShowAddKey(false);
        setNewKeyName('');
        setImportPrivateKey('');
        loadKeys();
      } else {
        const errorMsg = response?.error?.message || response?.error || 'Failed to add key';
        console.error('[KeyList] Error adding key:', errorMsg);

        // If vault is locked, refresh status which will redirect to unlock screen
        if (errorMsg === 'Vault is locked' || errorMsg.includes('locked')) {
          console.log('[KeyList] Vault is locked, refreshing status...');
          onRefresh();
          return;
        }

        setError(errorMsg);
      }
    } catch (err) {
      console.error('[KeyList] Exception adding key:', err);
      setError(err instanceof Error ? err.message : 'Failed to add key');
    }

    setActionLoading(false);
  };

  const handleRemoveKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to remove this key? This cannot be undone.')) {
      return;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'REMOVE_KEY',
        keyId
      });

      if (response.success) {
        loadKeys();
      }
    } catch (err) {
      console.error('Failed to remove key:', err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const truncateAddress = (address: string): string => {
    if (!address) return '';
    if (address.length <= 20) return address;
    return `${address.slice(0, 10)}...${address.slice(-8)}`;
  };

  // ===========================================================================
  // Render Add Key Modal
  // ===========================================================================

  const renderAddKeyModal = () => (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Add New Key</span>
        <button className="btn-icon" onClick={() => setShowAddKey(false)}>
          ✕
        </button>
      </div>

      <div className="form-group">
        <label className="form-label">Key Type</label>
        <select
          className="form-input"
          value={newKeyType}
          onChange={(e) => setNewKeyType(e.target.value as 'ed25519' | 'secp256k1')}
        >
          <option value="ed25519">ED25519 (Accumulate)</option>
          <option value="secp256k1">secp256k1 (Ethereum)</option>
        </select>
      </div>

      <div className="form-group">
        <label className="form-label">Name (optional)</label>
        <input
          type="text"
          className="form-input"
          value={newKeyName}
          onChange={(e) => setNewKeyName(e.target.value)}
          placeholder="e.g., Main Wallet"
        />
      </div>

      <div className="form-group">
        <label className="form-label">Method</label>
        <div className="flex gap-8">
          {vaultStatus.hasMnemonic && (
            <button
              className={`btn ${addKeyMode === 'derive' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setAddKeyMode('derive')}
            >
              Derive
            </button>
          )}
          <button
            className={`btn ${addKeyMode === 'generate' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setAddKeyMode('generate')}
          >
            Random
          </button>
          <button
            className={`btn ${addKeyMode === 'import' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setAddKeyMode('import')}
          >
            Import
          </button>
        </div>
        <p className="form-hint mt-8">
          {addKeyMode === 'derive' && 'Derive from your recovery phrase (recommended)'}
          {addKeyMode === 'generate' && 'Generate a new random key'}
          {addKeyMode === 'import' && 'Import an existing private key'}
        </p>
      </div>

      {addKeyMode === 'import' && (
        <div className="form-group">
          <label className="form-label">Private Key (hex)</label>
          <input
            type="password"
            className="form-input"
            value={importPrivateKey}
            onChange={(e) => setImportPrivateKey(e.target.value)}
            placeholder="Enter private key..."
          />
        </div>
      )}

      {error && <p className="form-error mb-16">{error}</p>}

      <button
        className="btn btn-primary btn-full"
        onClick={handleAddKey}
        disabled={actionLoading || (addKeyMode === 'import' && !importPrivateKey)}
      >
        {actionLoading ? 'Adding...' : 'Add Key'}
      </button>
    </div>
  );

  // ===========================================================================
  // Main Render
  // ===========================================================================

  return (
    <div className="app-container">
      <header className="header">
        <div className="header-title">
          <span>🔐</span>
          <h1>Certen Key Vault</h1>
        </div>
        <div className="header-actions">
          <button className="btn-icon" onClick={onRefresh} title="Refresh">
            ↻
          </button>
          <button className="btn-icon" onClick={onLock} title="Lock">
            🔒
          </button>
        </div>
      </header>

      <div className="content">
        {/* Network Badge */}
        <div className="flex justify-between items-center mb-16">
          <span className="card-badge">{vaultStatus.network}</span>
          <span className="text-secondary" style={{ fontSize: '12px' }}>
            {keys.length} key{keys.length !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Add Key Section */}
        {showAddKey ? (
          renderAddKeyModal()
        ) : (
          <button
            className="btn btn-primary btn-full mb-16"
            onClick={() => setShowAddKey(true)}
          >
            + Add Key
          </button>
        )}

        {/* Key List */}
        {loading ? (
          <div className="loading">
            <div className="spinner" />
          </div>
        ) : keys.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🔑</div>
            <p>No keys yet</p>
            <p className="form-hint mt-8">Add a key to get started</p>
          </div>
        ) : (
          <div className="key-list">
            {keys.map((key) => (
              <div key={key.id} className="key-card">
                <div className="key-icon">
                  {key.type === 'ed25519' ? '🌐' : '💎'}
                </div>
                <div className="key-info">
                  <div className="key-name">{key.name}</div>
                  <div
                    className="key-address"
                    onClick={() => copyToClipboard(
                      key.metadata.accumulateUrl || key.metadata.evmAddress || key.publicKey
                    )}
                    title="Click to copy"
                    style={{ cursor: 'pointer' }}
                  >
                    {truncateAddress(key.metadata.accumulateUrl || key.metadata.evmAddress || key.publicKey)}
                  </div>
                </div>
                <span className="key-type">
                  {key.type === 'ed25519' ? 'ACC' : 'ETH'}
                </span>
                <button
                  className="btn-icon"
                  onClick={() => handleRemoveKey(key.id)}
                  title="Remove key"
                  style={{ color: '#ef4444' }}
                >
                  🗑
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <footer className="footer">
        Certen Protocol v1.0.0
      </footer>
    </div>
  );
};

export default KeyList;
