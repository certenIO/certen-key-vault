/**
 * Certen Key Vault - Key Selection Page
 *
 * Allows users to select which key to use for a specific operation.
 */

import React, { useState, useEffect } from 'react';
import { StoredKey } from '../../shared/types';

// =============================================================================
// Types
// =============================================================================

interface KeySelectionProps {
  onComplete: () => void;
  onCancel: () => void;
}

interface PendingSelection {
  requestId: string;
  keyType?: string;
  purpose?: string;
  origin: string;
}

// =============================================================================
// KeySelection Component
// =============================================================================

const KeySelection: React.FC<KeySelectionProps> = ({ onComplete, onCancel }) => {
  const [keys, setKeys] = useState<StoredKey[]>([]);
  const [keyHashes, setKeyHashes] = useState<Record<string, string>>({});
  const [selection, setSelection] = useState<PendingSelection | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedKeyId, setSelectedKeyId] = useState<string | null>(null);

  // Load pending selection and keys on mount
  useEffect(() => {
    loadSelectionAndKeys();
  }, []);

  const loadSelectionAndKeys = async () => {
    setLoading(true);
    try {
      // Get pending selection request
      const selectionResponse = await chrome.runtime.sendMessage({ type: 'GET_PENDING_KEY_SELECTION' });
      if (!selectionResponse.selection) {
        setError('No pending key selection request');
        setLoading(false);
        return;
      }
      setSelection(selectionResponse.selection);

      // Get available keys
      const keysResponse = await chrome.runtime.sendMessage({
        type: 'GET_KEYS',
        keyType: selectionResponse.selection.keyType
      });

      if (keysResponse.keys) {
        setKeys(keysResponse.keys);
        // Pre-select first key
        if (keysResponse.keys.length > 0) {
          setSelectedKeyId(keysResponse.keys[0].id);
        }
        // Compute hashes for all keys
        await computeHashes(keysResponse.keys);
      }
    } catch (err) {
      console.error('Failed to load:', err);
      setError('Failed to load key selection request');
    }
    setLoading(false);
  };

  const computeHashes = async (keyList: StoredKey[]) => {
    const hashes: Record<string, string> = {};
    for (const key of keyList) {
      try {
        const publicKeyBytes = new Uint8Array(
          key.publicKey.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
        );
        const hashBuffer = await crypto.subtle.digest('SHA-256', publicKeyBytes);
        const hashArray = new Uint8Array(hashBuffer);
        hashes[key.id] = Array.from(hashArray)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      } catch (err) {
        hashes[key.id] = 'Error computing hash';
      }
    }
    setKeyHashes(hashes);
  };

  const handleConfirm = async () => {
    if (!selection || !selectedKeyId) return;

    setSubmitting(true);
    setError(null);

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'COMPLETE_KEY_SELECTION',
        requestId: selection.requestId,
        keyId: selectedKeyId
      });

      if (response.success) {
        onComplete();
      } else {
        setError(response.error?.message || 'Failed to complete selection');
      }
    } catch (err) {
      setError('Failed to complete selection');
    }

    setSubmitting(false);
  };

  const handleReject = async () => {
    if (!selection) {
      onCancel();
      return;
    }

    try {
      await chrome.runtime.sendMessage({
        type: 'REJECT_KEY_SELECTION',
        requestId: selection.requestId,
        reason: 'User cancelled'
      });
    } catch (err) {
      console.error('Failed to reject:', err);
    }

    onCancel();
  };

  const truncateAddress = (address: string): string => {
    if (!address) return '';
    if (address.length <= 20) return address;
    return `${address.slice(0, 10)}...${address.slice(-8)}`;
  };

  // ===========================================================================
  // Render
  // ===========================================================================

  if (loading) {
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

  if (!selection || keys.length === 0) {
    return (
      <div className="app-container">
        <header className="header">
          <div className="header-title">
            <span>🔐</span>
            <h1>Select Key</h1>
          </div>
        </header>
        <div className="content">
          <div className="empty-state">
            <div className="empty-state-icon">⚠️</div>
            <p>{error || 'No keys available'}</p>
            <button className="btn btn-secondary mt-16" onClick={handleReject}>
              Close
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <header className="header">
        <div className="header-title">
          <span>🔑</span>
          <h1>Select Key</h1>
        </div>
      </header>

      <div className="content">
        {/* Request Info */}
        <div className="card mb-16">
          <div className="card-header">
            <span className="card-title">Key Request</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">From</span>
            <span className="detail-value" style={{ fontSize: '12px' }}>
              {truncateAddress(selection.origin)}
            </span>
          </div>
          {selection.purpose && (
            <div className="detail-row">
              <span className="detail-label">Purpose</span>
              <span className="detail-value">{selection.purpose}</span>
            </div>
          )}
          {selection.keyType && (
            <div className="detail-row">
              <span className="detail-label">Key Type</span>
              <span className="detail-value">{selection.keyType.toUpperCase()}</span>
            </div>
          )}
        </div>

        {/* Key List */}
        <p className="form-label mb-8">Choose a key to use:</p>
        <div className="key-list">
          {keys.map((key) => {
            const isSelected = selectedKeyId === key.id;
            const primaryAddress = key.metadata.accumulateUrl || key.metadata.evmAddress || key.publicKey;

            return (
              <div
                key={key.id}
                className={`key-card ${isSelected ? 'selected' : ''}`}
                onClick={() => setSelectedKeyId(key.id)}
                style={{
                  cursor: 'pointer',
                  border: isSelected ? '2px solid #3b82f6' : '1px solid #374151',
                  backgroundColor: isSelected ? 'rgba(59, 130, 246, 0.1)' : undefined
                }}
              >
                <div className="key-icon">
                  {key.type === 'ed25519' ? '🌐' : key.type === 'secp256k1' ? '💎' : '🔐'}
                </div>
                <div className="key-info">
                  <div className="key-name">{key.name}</div>
                  <div className="key-address" style={{ fontSize: '11px' }}>
                    {truncateAddress(primaryAddress)}
                  </div>
                  <div className="key-address" style={{ fontSize: '10px', color: '#9ca3af', marginTop: '4px' }}>
                    Hash: {truncateAddress(keyHashes[key.id] || 'Computing...')}
                  </div>
                </div>
                <span className="key-type">
                  {key.type === 'ed25519' ? 'ACC' : key.type === 'secp256k1' ? 'ETH' : 'BLS'}
                </span>
                {isSelected && (
                  <span style={{ color: '#22c55e', fontSize: '18px' }}>✓</span>
                )}
              </div>
            );
          })}
        </div>

        {/* Selected Key Details */}
        {selectedKeyId && (
          <div className="card mt-16">
            <div className="card-header">
              <span className="card-title">Selected Key Details</span>
            </div>
            <div className="detail-row">
              <span className="detail-label">Public Key</span>
              <span className="detail-value" style={{ fontSize: '10px', fontFamily: 'monospace' }}>
                {truncateAddress(keys.find(k => k.id === selectedKeyId)?.publicKey || '')}
              </span>
            </div>
            <div className="detail-row">
              <span className="detail-label">SHA-256 Hash</span>
              <span className="detail-value" style={{ fontSize: '10px', fontFamily: 'monospace' }}>
                {truncateAddress(keyHashes[selectedKeyId] || 'Computing...')}
              </span>
            </div>
            <p className="form-hint mt-8">
              This SHA-256 hash will be added to your ADI's key page.
            </p>
          </div>
        )}

        {error && <p className="form-error mt-16">{error}</p>}

        {/* Action Buttons */}
        <div className="mt-16">
          <button
            className="btn btn-primary btn-full"
            onClick={handleConfirm}
            disabled={submitting || !selectedKeyId}
          >
            {submitting ? 'Confirming...' : 'Use This Key'}
          </button>
          <button
            className="btn btn-secondary btn-full mt-8"
            onClick={handleReject}
            disabled={submitting}
          >
            Cancel
          </button>
        </div>
      </div>

      <footer className="footer">
        Certen Protocol v1.0.0
      </footer>
    </div>
  );
};

export default KeySelection;
