/**
 * Certen Key Vault - Sign Approval Page
 *
 * Shows transaction details and allows user to approve or reject signing.
 */

import React, { useState, useEffect } from 'react';
import { SignRequest, StoredKey } from '../../shared/types';

// =============================================================================
// Types
// =============================================================================

interface SignApprovalProps {
  onComplete: () => void;
  onCancel: () => void;
}

// =============================================================================
// SignApproval Component
// =============================================================================

const SignApproval: React.FC<SignApprovalProps> = ({ onComplete, onCancel }) => {
  const [request, setRequest] = useState<SignRequest | null>(null);
  const [suggestedKeyId, setSuggestedKeyId] = useState<string | undefined>();
  const [selectedKeyId, setSelectedKeyId] = useState<string>('');
  const [keys, setKeys] = useState<StoredKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load pending request and keys on mount
  useEffect(() => {
    loadPendingRequest();
    loadKeys();
  }, []);

  // Auto-select suggested key
  useEffect(() => {
    if (suggestedKeyId && !selectedKeyId) {
      setSelectedKeyId(suggestedKeyId);
    }
  }, [suggestedKeyId, keys]);

  const loadPendingRequest = async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_PENDING_SIGN_REQUEST' });
      if (response.request) {
        setRequest(response.request);
        setSuggestedKeyId(response.suggestedKeyId);
      } else {
        // No pending request
        onCancel();
      }
    } catch (err) {
      console.error('Failed to load pending request:', err);
      setError('Failed to load request');
    }
    setLoading(false);
  };

  const loadKeys = async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_KEYS' });
      if (response.keys) {
        setKeys(response.keys);
      }
    } catch (err) {
      console.error('Failed to load keys:', err);
    }
  };

  const handleApprove = async () => {
    if (!selectedKeyId || !request) return;

    setProcessing(true);
    setError(null);

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'APPROVE_SIGN_REQUEST',
        requestId: request.id,
        keyId: selectedKeyId
      });

      if (response.success) {
        onComplete();
      } else {
        setError(response.error?.message || 'Failed to sign');
      }
    } catch (err) {
      setError('Failed to sign');
      console.error(err);
    }

    setProcessing(false);
  };

  const handleReject = async () => {
    if (!request) return;

    setProcessing(true);

    try {
      await chrome.runtime.sendMessage({
        type: 'REJECT_SIGN_REQUEST',
        requestId: request.id,
        reason: 'User rejected'
      });
      onCancel();
    } catch (err) {
      console.error('Failed to reject:', err);
      onCancel();
    }
  };

  const truncate = (str: string, length: number = 20): string => {
    if (!str) return '';
    if (str.length <= length) return str;
    return `${str.slice(0, length / 2)}...${str.slice(-length / 2)}`;
  };

  // Filter keys by type based on request
  const getFilteredKeys = (): StoredKey[] => {
    if (!request) return keys;

    // For Accumulate requests, show ED25519 keys
    if (request.type.startsWith('acc_') || request.type === 'certen_signIntent') {
      return keys.filter(k => k.type === 'ed25519');
    }

    // For Ethereum requests, show secp256k1 keys
    if (request.type.startsWith('eth_')) {
      return keys.filter(k => k.type === 'secp256k1');
    }

    return keys;
  };

  // Get transaction details for display
  const getTransactionDetails = (): { label: string; value: string }[] => {
    if (!request) return [];

    const details: { label: string; value: string }[] = [];

    // Add human-readable info if available
    const data = request.data as any;

    if (data.humanReadable) {
      if (data.humanReadable.action) {
        details.push({ label: 'Action', value: data.humanReadable.action });
      }
      if (data.humanReadable.from) {
        details.push({ label: 'From', value: truncate(data.humanReadable.from, 30) });
      }
      if (data.humanReadable.to) {
        details.push({ label: 'To', value: truncate(data.humanReadable.to, 30) });
      }
      if (data.humanReadable.amount) {
        details.push({ label: 'Amount', value: data.humanReadable.amount });
      }
    }

    // Add technical details
    if (data.kind === 'acc_transaction') {
      details.push({ label: 'Principal', value: truncate(data.principal, 30) });
      if (data.transactionType) {
        details.push({ label: 'Type', value: data.transactionType });
      }
    }

    if (data.kind === 'certen_intent') {
      details.push({ label: 'ADI', value: truncate(data.adiUrl, 30) });
      details.push({ label: 'Action', value: data.actionType });
      if (data.description) {
        details.push({ label: 'Description', value: data.description });
      }
    }

    // Always show hash
    const hash = data.transactionHash || data.hash || data.intentId;
    if (hash) {
      details.push({ label: 'Hash', value: truncate(hash, 24) });
    }

    return details;
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
            <p className="mt-16">Loading request...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!request) {
    return (
      <div className="app-container">
        <div className="content">
          <div className="empty-state">
            <div className="empty-state-icon">✓</div>
            <p>No pending requests</p>
          </div>
        </div>
      </div>
    );
  }

  const filteredKeys = getFilteredKeys();
  const details = getTransactionDetails();

  return (
    <div className="app-container">
      <header className="header">
        <div className="header-title">
          <span>📝</span>
          <h1>Signature Request</h1>
        </div>
      </header>

      <div className="content">
        <div className="approval-container">
          {/* Origin */}
          <div className="approval-origin">
            <strong>From:</strong> {request.origin}
          </div>

          {/* Transaction Details */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Transaction Details</span>
              <span className="card-badge secondary">
                {request.type.replace('_', ' ').replace('acc ', 'ACC ').replace('eth ', 'ETH ')}
              </span>
            </div>

            <div className="approval-details">
              {details.map((detail, index) => (
                <div key={index} className="detail-row">
                  <span className="detail-label">{detail.label}</span>
                  <span className="detail-value">{detail.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Key Selection */}
          <div className="form-group">
            <label className="form-label">Sign with:</label>
            {filteredKeys.length === 0 ? (
              <div className="empty-state" style={{ padding: '16px' }}>
                <p>No compatible keys found</p>
                <p className="form-hint">
                  {request.type.startsWith('eth_')
                    ? 'Add an Ethereum (secp256k1) key'
                    : 'Add an Accumulate (ED25519) key'}
                </p>
              </div>
            ) : (
              <div className="key-list">
                {filteredKeys.map((key) => (
                  <div
                    key={key.id}
                    className={`key-card ${selectedKeyId === key.id ? 'selected' : ''}`}
                    onClick={() => setSelectedKeyId(key.id)}
                  >
                    <div className="key-icon">
                      {key.type === 'ed25519' ? '🌐' : '💎'}
                    </div>
                    <div className="key-info">
                      <div className="key-name">{key.name}</div>
                      <div className="key-address">
                        {truncate(key.metadata.accumulateUrl || key.metadata.evmAddress || key.publicKey, 24)}
                      </div>
                    </div>
                    {selectedKeyId === key.id && (
                      <span style={{ color: '#22c55e' }}>✓</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {error && <p className="form-error mb-16">{error}</p>}

          {/* Actions */}
          <div className="approval-actions">
            <button
              className="btn btn-secondary"
              onClick={handleReject}
              disabled={processing}
            >
              Reject
            </button>
            <button
              className="btn btn-primary"
              onClick={handleApprove}
              disabled={processing || !selectedKeyId}
            >
              {processing ? 'Signing...' : 'Sign'}
            </button>
          </div>
        </div>
      </div>

      <footer className="footer">
        Review carefully before signing
      </footer>
    </div>
  );
};

export default SignApproval;
