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
  const [newKeyType, setNewKeyType] = useState<'ed25519' | 'secp256k1' | 'bls12381'>('ed25519');
  const [addKeyMode, setAddKeyMode] = useState<'derive' | 'generate' | 'import' | 'mnemonic'>('derive');
  const [importPrivateKey, setImportPrivateKey] = useState('');
  const [importMnemonic, setImportMnemonic] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [expandedKeyId, setExpandedKeyId] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [resetMnemonic, setResetMnemonic] = useState('');
  const [resetPassword, setResetPassword] = useState('');
  const [resetConfirmPassword, setResetConfirmPassword] = useState('');
  const [resetLoading, setResetLoading] = useState(false);

  // Secret reveal state
  const [showMnemonic, setShowMnemonic] = useState(false);
  const [revealedMnemonic, setRevealedMnemonic] = useState<string | null>(null);
  const [mnemonicLoading, setMnemonicLoading] = useState(false);
  const [showPrivateKeySection, setShowPrivateKeySection] = useState(false);
  const [selectedKeyForExport, setSelectedKeyForExport] = useState<string | null>(null);
  const [revealedPrivateKey, setRevealedPrivateKey] = useState<string | null>(null);
  const [privateKeyLoading, setPrivateKeyLoading] = useState(false);

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

      const defaultName = newKeyType === 'ed25519' ? 'Multi-Chain' : newKeyType === 'secp256k1' ? 'EVM' : 'Validator';

      if (addKeyMode === 'derive') {
        response = await chrome.runtime.sendMessage({
          type: 'DERIVE_KEY',
          keyType: newKeyType,
          name: newKeyName || `${defaultName} Key`
        });
      } else if (addKeyMode === 'generate') {
        response = await chrome.runtime.sendMessage({
          type: 'GENERATE_KEY',
          keyType: newKeyType,
          name: newKeyName || `${defaultName} Key`
        });
      } else if (addKeyMode === 'import') {
        response = await chrome.runtime.sendMessage({
          type: 'IMPORT_KEY',
          keyType: newKeyType,
          privateKey: importPrivateKey.trim(),
          name: newKeyName || `Imported ${defaultName} Key`
        });
      } else if (addKeyMode === 'mnemonic') {
        response = await chrome.runtime.sendMessage({
          type: 'IMPORT_MNEMONIC',
          mnemonic: importMnemonic.trim(),
          keyType: newKeyType,
          name: newKeyName || `${defaultName} Key`
        });
      }

      console.log('[KeyList] Response from add key:', response);
      if (response?.success) {
        setShowAddKey(false);
        setNewKeyName('');
        setImportPrivateKey('');
        setImportMnemonic('');
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

    setError(null);
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'REMOVE_KEY',
        keyId
      });

      if (response.success) {
        loadKeys();
      } else {
        const errorMsg = response?.error?.message || response?.error || 'Failed to remove key';
        console.error('[KeyList] Error removing key:', errorMsg);

        // If vault is locked, refresh status which will redirect to unlock screen
        if (errorMsg === 'Vault is locked' || errorMsg.includes('locked')) {
          console.log('[KeyList] Vault is locked, refreshing status...');
          onRefresh();
          return;
        }

        setError(errorMsg);
      }
    } catch (err) {
      console.error('Failed to remove key:', err);
      setError(err instanceof Error ? err.message : 'Failed to remove key');
    }
  };

  const handleResetAndRecover = async () => {
    setError(null);

    if (resetPassword.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (resetPassword !== resetConfirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (!resetMnemonic.trim()) {
      setError('Please enter your recovery phrase');
      return;
    }

    setResetLoading(true);

    try {
      // Step 1: Reset the vault
      const resetResponse = await chrome.runtime.sendMessage({ type: 'VAULT_RESET' });
      if (!resetResponse.success) {
        setError(resetResponse.error || 'Failed to reset vault');
        setResetLoading(false);
        return;
      }

      // Step 2: Initialize with mnemonic
      const initResponse = await chrome.runtime.sendMessage({
        type: 'VAULT_INITIALIZE',
        password: resetPassword,
        mnemonic: resetMnemonic.trim()
      });

      if (!initResponse.success) {
        setError(initResponse.error || 'Failed to recover vault');
        setResetLoading(false);
        return;
      }

      // Success - reload
      setShowResetConfirm(false);
      setShowSettings(false);
      setResetMnemonic('');
      setResetPassword('');
      setResetConfirmPassword('');
      onRefresh();
    } catch (err) {
      console.error('Reset failed:', err);
      setError(err instanceof Error ? err.message : 'Reset failed');
    }

    setResetLoading(false);
  };

  const handleRevealMnemonic = async () => {
    setMnemonicLoading(true);
    setError(null);
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_MNEMONIC' });
      if (response.mnemonic) {
        setRevealedMnemonic(response.mnemonic);
        setShowMnemonic(true);
      } else {
        setError(response.error?.message || 'Failed to retrieve recovery phrase');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve recovery phrase');
    }
    setMnemonicLoading(false);
  };

  const handleHideMnemonic = () => {
    setShowMnemonic(false);
    setRevealedMnemonic(null);
  };

  const handleRevealPrivateKey = async (keyId: string) => {
    setPrivateKeyLoading(true);
    setError(null);
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_KEY_WITH_PRIVATE', keyId });
      if (response.key) {
        setRevealedPrivateKey(response.key.privateKey);
        setSelectedKeyForExport(keyId);
      } else {
        setError(response.error?.message || 'Failed to retrieve private key');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve private key');
    }
    setPrivateKeyLoading(false);
  };

  const handleHidePrivateKey = () => {
    setRevealedPrivateKey(null);
    setSelectedKeyForExport(null);
  };

  const resetSettingsState = () => {
    setShowResetConfirm(false);
    setShowMnemonic(false);
    setRevealedMnemonic(null);
    setShowPrivateKeySection(false);
    setSelectedKeyForExport(null);
    setRevealedPrivateKey(null);
    setError(null);
  };

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const formatDate = (timestamp: number): string => {
    return new Date(timestamp).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Store computed SHA-256 hashes for each key
  const [keyHashes, setKeyHashes] = useState<Record<string, string>>({});

  // Compute SHA-256 hash of public key (what Accumulate stores in key pages)
  const computeSHA256Hash = async (publicKeyHex: string): Promise<string> => {
    try {
      const publicKeyBytes = new Uint8Array(
        publicKeyHex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
      );
      const hashBuffer = await crypto.subtle.digest('SHA-256', publicKeyBytes);
      const hashArray = new Uint8Array(hashBuffer);
      return Array.from(hashArray)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    } catch (error) {
      console.error('Failed to compute SHA-256 hash:', error);
      return publicKeyHex.slice(0, 16) + '...(error)';
    }
  };

  // Compute hashes for all keys when keys change
  useEffect(() => {
    const computeHashes = async () => {
      const hashes: Record<string, string> = {};
      for (const key of keys) {
        hashes[key.id] = await computeSHA256Hash(key.publicKey);
      }
      setKeyHashes(hashes);
    };
    if (keys.length > 0) {
      computeHashes();
    }
  }, [keys]);

  const getKeyHash = (keyId: string): string => {
    return keyHashes[keyId] || 'Computing...';
  };

  const toggleKeyExpanded = (keyId: string) => {
    setExpandedKeyId(expandedKeyId === keyId ? null : keyId);
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
          onChange={(e) => setNewKeyType(e.target.value as 'ed25519' | 'secp256k1' | 'bls12381')}
        >
          <option value="ed25519">ED25519 - Accumulate, Solana, Aptos, Sui, NEAR, TON</option>
          <option value="secp256k1">secp256k1 - Ethereum, EVMs, Bitcoin, Cosmos, TRON</option>
          <option value="bls12381">BLS12-381 - Validators</option>
        </select>
        <p className="form-hint mt-8">
          {newKeyType === 'ed25519' && 'Works with: Accumulate, Solana, Aptos, Sui, NEAR, TON'}
          {newKeyType === 'secp256k1' && 'Works with: Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Bitcoin, Cosmos chains, TRON'}
          {newKeyType === 'bls12381' && 'Works with: Ethereum validators, BLS signature schemes'}
        </p>
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
        <div className="method-buttons">
          {vaultStatus.hasMnemonic && (
            <button
              className={`btn btn-small ${addKeyMode === 'derive' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setAddKeyMode('derive')}
            >
              Derive
            </button>
          )}
          <button
            className={`btn btn-small ${addKeyMode === 'generate' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setAddKeyMode('generate')}
          >
            Random
          </button>
          <button
            className={`btn btn-small ${addKeyMode === 'import' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setAddKeyMode('import')}
          >
            Private Key
          </button>
          <button
            className={`btn btn-small ${addKeyMode === 'mnemonic' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setAddKeyMode('mnemonic')}
          >
            Mnemonic
          </button>
        </div>
        <p className="form-hint mt-8">
          {addKeyMode === 'derive' && 'Derive from your stored recovery phrase (recommended)'}
          {addKeyMode === 'generate' && 'Generate a new random key (not recoverable from mnemonic)'}
          {addKeyMode === 'import' && 'Import from a hex-encoded private key'}
          {addKeyMode === 'mnemonic' && 'Import from a BIP-39 mnemonic phrase (12 or 24 words)'}
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

      {addKeyMode === 'mnemonic' && (
        <div className="form-group">
          <label className="form-label">Mnemonic Phrase</label>
          <textarea
            className="form-input form-textarea"
            value={importMnemonic}
            onChange={(e) => setImportMnemonic(e.target.value)}
            placeholder="Enter 12 or 24 word recovery phrase..."
            rows={3}
          />
        </div>
      )}

      {error && <p className="form-error mb-16">{error}</p>}

      <button
        className="btn btn-primary btn-full"
        onClick={handleAddKey}
        disabled={actionLoading || (addKeyMode === 'import' && !importPrivateKey) || (addKeyMode === 'mnemonic' && !importMnemonic)}
      >
        {actionLoading ? 'Adding...' : 'Add Key'}
      </button>
    </div>
  );

  // ===========================================================================
  // Render Settings Modal
  // ===========================================================================

  const renderSettingsModal = () => (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Settings</span>
        <button className="btn-icon" onClick={() => { setShowSettings(false); resetSettingsState(); }}>
          ✕
        </button>
      </div>

      {!showResetConfirm ? (
        <>
          {/* Recovery Phrase Section */}
          {vaultStatus.hasMnemonic && (
            <div className="form-group" style={{ borderBottom: '1px solid #333', paddingBottom: '16px', marginBottom: '16px' }}>
              <p className="form-label">Recovery Phrase</p>
              {!showMnemonic ? (
                <>
                  <p className="form-hint" style={{ marginBottom: '12px' }}>
                    Reveal your 12/24 word recovery phrase. Keep it safe and never share it.
                  </p>
                  <button
                    className="btn btn-secondary btn-full"
                    onClick={handleRevealMnemonic}
                    disabled={mnemonicLoading}
                  >
                    {mnemonicLoading ? 'Loading...' : 'Show Recovery Phrase'}
                  </button>
                </>
              ) : (
                <>
                  <p className="form-hint" style={{ color: '#ef4444', marginBottom: '8px' }}>
                    Never share your recovery phrase with anyone!
                  </p>
                  <div style={{
                    backgroundColor: '#1a1a1a',
                    border: '1px solid #ef4444',
                    borderRadius: '8px',
                    padding: '12px',
                    fontFamily: 'monospace',
                    fontSize: '13px',
                    wordBreak: 'break-word',
                    marginBottom: '12px'
                  }}>
                    {revealedMnemonic}
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      className="btn btn-secondary"
                      style={{ flex: 1 }}
                      onClick={() => copyToClipboard(revealedMnemonic!, 'mnemonic')}
                    >
                      {copiedField === 'mnemonic' ? 'Copied!' : 'Copy'}
                    </button>
                    <button
                      className="btn btn-secondary"
                      style={{ flex: 1 }}
                      onClick={handleHideMnemonic}
                    >
                      Hide
                    </button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Export Private Key Section */}
          <div className="form-group" style={{ borderBottom: '1px solid #333', paddingBottom: '16px', marginBottom: '16px' }}>
            <p className="form-label">Export Private Key</p>
            {!showPrivateKeySection ? (
              <>
                <p className="form-hint" style={{ marginBottom: '12px' }}>
                  Export a key's private key for use in another wallet.
                </p>
                <button
                  className="btn btn-secondary btn-full"
                  onClick={() => setShowPrivateKeySection(true)}
                  disabled={keys.length === 0}
                >
                  {keys.length === 0 ? 'No Keys Available' : 'Export Private Key'}
                </button>
              </>
            ) : (
              <>
                {!revealedPrivateKey ? (
                  <>
                    <p className="form-hint" style={{ marginBottom: '12px' }}>
                      Select a key to export:
                    </p>
                    <select
                      className="form-input"
                      style={{ marginBottom: '12px' }}
                      value={selectedKeyForExport || ''}
                      onChange={(e) => setSelectedKeyForExport(e.target.value || null)}
                    >
                      <option value="">-- Select a key --</option>
                      {keys.map((key) => (
                        <option key={key.id} value={key.id}>
                          {key.name} ({key.type})
                        </option>
                      ))}
                    </select>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ flex: 1 }}
                        onClick={() => setShowPrivateKeySection(false)}
                      >
                        Cancel
                      </button>
                      <button
                        className="btn btn-primary"
                        style={{ flex: 1 }}
                        onClick={() => selectedKeyForExport && handleRevealPrivateKey(selectedKeyForExport)}
                        disabled={!selectedKeyForExport || privateKeyLoading}
                      >
                        {privateKeyLoading ? 'Loading...' : 'Reveal'}
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <p className="form-hint" style={{ color: '#ef4444', marginBottom: '8px' }}>
                      Never share your private key with anyone!
                    </p>
                    <p className="form-hint" style={{ marginBottom: '8px' }}>
                      Key: {keys.find(k => k.id === selectedKeyForExport)?.name}
                    </p>
                    <div style={{
                      backgroundColor: '#1a1a1a',
                      border: '1px solid #ef4444',
                      borderRadius: '8px',
                      padding: '12px',
                      fontFamily: 'monospace',
                      fontSize: '11px',
                      wordBreak: 'break-all',
                      marginBottom: '12px'
                    }}>
                      {revealedPrivateKey}
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ flex: 1 }}
                        onClick={() => copyToClipboard(revealedPrivateKey!, 'privateKey')}
                      >
                        {copiedField === 'privateKey' ? 'Copied!' : 'Copy'}
                      </button>
                      <button
                        className="btn btn-secondary"
                        style={{ flex: 1 }}
                        onClick={handleHidePrivateKey}
                      >
                        Hide
                      </button>
                    </div>
                  </>
                )}
              </>
            )}
          </div>

          {/* Vault Info */}
          <div className="form-group">
            <p className="form-hint" style={{ marginBottom: '16px' }}>
              Vault has {vaultStatus.hasMnemonic ? 'a stored recovery phrase' : 'no stored recovery phrase'}.
            </p>
          </div>

          {error && <p className="form-error mb-16">{error}</p>}

          <div className="danger-zone" style={{
            borderTop: '1px solid #ef4444',
            paddingTop: '16px',
            marginTop: '16px'
          }}>
            <p className="form-label" style={{ color: '#ef4444' }}>Danger Zone</p>
            <p className="form-hint" style={{ marginBottom: '12px' }}>
              Reset your vault and recover from a mnemonic phrase. This will delete all existing keys.
            </p>
            <button
              className="btn btn-full"
              style={{ backgroundColor: '#ef4444', color: 'white' }}
              onClick={() => setShowResetConfirm(true)}
            >
              Reset & Recover from Mnemonic
            </button>
          </div>
        </>
      ) : (
        <>
          <div className="form-group">
            <p className="form-hint" style={{ color: '#ef4444', marginBottom: '16px' }}>
              ⚠️ This will DELETE all existing keys and reset your vault. Only proceed if you have your recovery phrase.
            </p>
          </div>

          <div className="form-group">
            <label className="form-label">Recovery Phrase</label>
            <textarea
              className="form-input form-textarea"
              value={resetMnemonic}
              onChange={(e) => setResetMnemonic(e.target.value)}
              placeholder="Enter your 12 or 24 word recovery phrase..."
              rows={3}
            />
          </div>

          <div className="form-group">
            <label className="form-label">New Password</label>
            <input
              type="password"
              className="form-input"
              value={resetPassword}
              onChange={(e) => setResetPassword(e.target.value)}
              placeholder="Enter new password (min 8 chars)"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Confirm Password</label>
            <input
              type="password"
              className="form-input"
              value={resetConfirmPassword}
              onChange={(e) => setResetConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
            />
          </div>

          {error && <p className="form-error mb-16">{error}</p>}

          <button
            className="btn btn-full"
            style={{ backgroundColor: '#ef4444', color: 'white' }}
            onClick={handleResetAndRecover}
            disabled={resetLoading}
          >
            {resetLoading ? 'Resetting...' : 'Reset & Recover'}
          </button>

          <button
            className="btn btn-secondary btn-full mt-8"
            onClick={() => { setShowResetConfirm(false); setError(null); }}
            disabled={resetLoading}
          >
            Cancel
          </button>
        </>
      )}
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
          <button className="btn-icon" onClick={() => setShowSettings(true)} title="Settings">
            ⚙
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

        {/* Settings Modal */}
        {showSettings && renderSettingsModal()}

        {/* Add Key Section */}
        {!showSettings && (showAddKey ? (
          renderAddKeyModal()
        ) : (
          <button
            className="btn btn-primary btn-full mb-16"
            onClick={() => setShowAddKey(true)}
          >
            + Add Key
          </button>
        ))}

        {/* Key List */}
        {!showSettings && (loading ? (
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
            {keys.map((key) => {
              const primaryAddress = key.metadata.accumulateUrl || key.metadata.evmAddress || key.metadata.blsPublicKey || key.publicKey;
              const isExpanded = expandedKeyId === key.id;

              return (
                <div key={key.id} className={`key-card-container ${isExpanded ? 'expanded' : ''}`}>
                  <div
                    className={`key-card ${isExpanded ? 'selected' : ''}`}
                    onClick={() => toggleKeyExpanded(key.id)}
                  >
                    <div className="key-icon">
                      {key.type === 'ed25519' ? '🌐' : key.type === 'secp256k1' ? '💎' : '🔐'}
                    </div>
                    <div className="key-info">
                      <div className="key-name">{key.name}</div>
                      <div className="key-address">
                        {truncateAddress(primaryAddress)}
                      </div>
                    </div>
                    <span className="key-type">
                      {key.type === 'ed25519' ? 'ACC' : key.type === 'secp256k1' ? 'ETH' : 'BLS'}
                    </span>
                    <button
                      className="btn-icon"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(primaryAddress, `addr-${key.id}`);
                      }}
                      title="Copy address"
                      style={{ color: copiedField === `addr-${key.id}` ? '#22c55e' : undefined }}
                    >
                      {copiedField === `addr-${key.id}` ? '✓' : '📋'}
                    </button>
                    <button
                      className="btn-icon"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRemoveKey(key.id);
                      }}
                      title="Remove key"
                      style={{ color: '#ef4444' }}
                    >
                      🗑
                    </button>
                  </div>

                  {/* Expanded Key Details */}
                  {isExpanded && (
                    <div className="key-details">
                      <div className="detail-row">
                        <span className="detail-label">Public Key</span>
                        <div className="detail-value-row">
                          <span className="detail-value truncate" title={key.publicKey}>
                            {truncateAddress(key.publicKey)}
                          </span>
                          <button
                            className="btn-icon-small"
                            onClick={() => copyToClipboard(key.publicKey, `pubkey-${key.id}`)}
                            title="Copy public key"
                          >
                            {copiedField === `pubkey-${key.id}` ? '✓' : '📋'}
                          </button>
                        </div>
                      </div>

                      <div className="detail-row">
                        <span className="detail-label">Key Hash (SHA-256)</span>
                        <div className="detail-value-row">
                          <span className="detail-value" style={{ fontFamily: 'monospace' }}>
                            {truncateAddress(getKeyHash(key.id))}
                          </span>
                          <button
                            className="btn-icon-small"
                            onClick={() => copyToClipboard(getKeyHash(key.id), `hash-${key.id}`)}
                            title="Copy SHA-256 hash (used in Accumulate key pages)"
                          >
                            {copiedField === `hash-${key.id}` ? '✓' : '📋'}
                          </button>
                        </div>
                      </div>

                      <div className="detail-row">
                        <span className="detail-label">Created</span>
                        <span className="detail-value">{formatDate(key.createdAt)}</span>
                      </div>

                      {key.lastUsedAt && (
                        <div className="detail-row">
                          <span className="detail-label">Last Used</span>
                          <span className="detail-value">{formatDate(key.lastUsedAt)}</span>
                        </div>
                      )}

                      {key.derivationPath && (
                        <div className="detail-row">
                          <span className="detail-label">Derivation Path</span>
                          <span className="detail-value" style={{ fontFamily: 'monospace' }}>
                            {key.derivationPath}
                          </span>
                        </div>
                      )}

                      {key.metadata.mnemonic && (
                        <div className="detail-row">
                          <span className="detail-label">Source</span>
                          <span className="detail-value">Derived from mnemonic</span>
                        </div>
                      )}

                      {/* Additional addresses for multi-chain keys */}
                      {key.metadata.solanaAddress && (
                        <div className="detail-row">
                          <span className="detail-label">Solana</span>
                          <div className="detail-value-row">
                            <span className="detail-value truncate">
                              {truncateAddress(key.metadata.solanaAddress)}
                            </span>
                            <button
                              className="btn-icon-small"
                              onClick={() => copyToClipboard(key.metadata.solanaAddress!, `sol-${key.id}`)}
                              title="Copy Solana address"
                            >
                              {copiedField === `sol-${key.id}` ? '✓' : '📋'}
                            </button>
                          </div>
                        </div>
                      )}

                      {key.metadata.aptosAddress && (
                        <div className="detail-row">
                          <span className="detail-label">Aptos</span>
                          <div className="detail-value-row">
                            <span className="detail-value truncate">
                              {truncateAddress(key.metadata.aptosAddress)}
                            </span>
                            <button
                              className="btn-icon-small"
                              onClick={() => copyToClipboard(key.metadata.aptosAddress!, `apt-${key.id}`)}
                              title="Copy Aptos address"
                            >
                              {copiedField === `apt-${key.id}` ? '✓' : '📋'}
                            </button>
                          </div>
                        </div>
                      )}

                      {key.metadata.suiAddress && (
                        <div className="detail-row">
                          <span className="detail-label">Sui</span>
                          <div className="detail-value-row">
                            <span className="detail-value truncate">
                              {truncateAddress(key.metadata.suiAddress)}
                            </span>
                            <button
                              className="btn-icon-small"
                              onClick={() => copyToClipboard(key.metadata.suiAddress!, `sui-${key.id}`)}
                              title="Copy Sui address"
                            >
                              {copiedField === `sui-${key.id}` ? '✓' : '📋'}
                            </button>
                          </div>
                        </div>
                      )}

                      {key.metadata.tonAddress && (
                        <div className="detail-row">
                          <span className="detail-label">TON</span>
                          <div className="detail-value-row">
                            <span className="detail-value truncate">
                              {truncateAddress(key.metadata.tonAddress)}
                            </span>
                            <button
                              className="btn-icon-small"
                              onClick={() => copyToClipboard(key.metadata.tonAddress!, `ton-${key.id}`)}
                              title="Copy TON address"
                            >
                              {copiedField === `ton-${key.id}` ? '✓' : '📋'}
                            </button>
                          </div>
                        </div>
                      )}

                      {key.metadata.nearAddress && (
                        <div className="detail-row">
                          <span className="detail-label">NEAR</span>
                          <div className="detail-value-row">
                            <span className="detail-value truncate">
                              {truncateAddress(key.metadata.nearAddress)}
                            </span>
                            <button
                              className="btn-icon-small"
                              onClick={() => copyToClipboard(key.metadata.nearAddress!, `near-${key.id}`)}
                              title="Copy NEAR address"
                            >
                              {copiedField === `near-${key.id}` ? '✓' : '📋'}
                            </button>
                          </div>
                        </div>
                      )}

                      {key.metadata.tronAddress && (
                        <div className="detail-row">
                          <span className="detail-label">TRON</span>
                          <div className="detail-value-row">
                            <span className="detail-value truncate">
                              {truncateAddress(key.metadata.tronAddress)}
                            </span>
                            <button
                              className="btn-icon-small"
                              onClick={() => copyToClipboard(key.metadata.tronAddress!, `tron-${key.id}`)}
                              title="Copy TRON address"
                            >
                              {copiedField === `tron-${key.id}` ? '✓' : '📋'}
                            </button>
                          </div>
                        </div>
                      )}

                      {key.metadata.cosmosAddresses && Object.keys(key.metadata.cosmosAddresses).length > 0 && (
                        <div className="detail-row">
                          <span className="detail-label">Cosmos Chains</span>
                          <div className="cosmos-addresses">
                            {Object.entries(key.metadata.cosmosAddresses).slice(0, 5).map(([chain, address]) => (
                              <div key={chain} className="detail-value-row" style={{ marginBottom: '4px' }}>
                                <span className="detail-value truncate" style={{ fontSize: '11px' }}>
                                  <strong>{chain}:</strong> {truncateAddress(address)}
                                </span>
                                <button
                                  className="btn-icon-small"
                                  onClick={() => copyToClipboard(address, `${chain}-${key.id}`)}
                                  title={`Copy ${chain} address`}
                                >
                                  {copiedField === `${chain}-${key.id}` ? '✓' : '📋'}
                                </button>
                              </div>
                            ))}
                            {Object.keys(key.metadata.cosmosAddresses).length > 5 && (
                              <span className="detail-value" style={{ fontSize: '10px', color: '#666' }}>
                                +{Object.keys(key.metadata.cosmosAddresses).length - 5} more chains
                              </span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      <footer className="footer">
        Certen Protocol v1.0.0
      </footer>
    </div>
  );
};

export default KeyList;
