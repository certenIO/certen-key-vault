/**
 * Certen Key Vault - Setup Page
 *
 * Initial vault setup with password creation and mnemonic generation.
 */

import React, { useState } from 'react';

// =============================================================================
// Types
// =============================================================================

interface SetupProps {
  onComplete: () => void;
}

type SetupStep = 'password' | 'mnemonic' | 'confirm';

// =============================================================================
// Setup Component
// =============================================================================

const Setup: React.FC<SetupProps> = ({ onComplete }) => {
  const [step, setStep] = useState<SetupStep>('password');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [mnemonic, setMnemonic] = useState<string[]>([]);
  const [importMode, setImportMode] = useState(false);
  const [importMnemonic, setImportMnemonic] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // ===========================================================================
  // Password Step
  // ===========================================================================

  const handlePasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Initialize vault (with or without imported mnemonic)
    initializeVault();
  };

  const initializeVault = async () => {
    setLoading(true);
    setError(null);

    try {
      const mnemonicToUse = importMode ? importMnemonic.trim() : undefined;

      const response = await chrome.runtime.sendMessage({
        type: 'VAULT_INITIALIZE',
        password,
        mnemonic: mnemonicToUse
      });

      if (!response.success) {
        setError(response.error || 'Failed to initialize vault');
        setLoading(false);
        return;
      }

      if (!importMode) {
        // Show generated mnemonic
        setMnemonic(response.mnemonic.split(' '));
        setStep('mnemonic');
      } else {
        // Import complete
        onComplete();
      }
    } catch (err) {
      setError('Failed to initialize vault');
      console.error(err);
    }

    setLoading(false);
  };

  // ===========================================================================
  // Render Password Step
  // ===========================================================================

  const renderPasswordStep = () => (
    <div className="setup-container">
      <div className="setup-icon">🔒</div>
      <h1 className="setup-title">Create Your Vault</h1>
      <p className="setup-description">
        Set a strong password to encrypt your keys.
        This password will be required to unlock your vault.
      </p>

      <form onSubmit={handlePasswordSubmit}>
        <div className="form-group text-left">
          <label className="form-label">Password</label>
          <div className="password-input-wrapper">
            <input
              type={showPassword ? 'text' : 'password'}
              className="form-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password (min 8 characters)"
              autoFocus
            />
            <button
              type="button"
              className="password-toggle"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? '👁' : '👀'}
            </button>
          </div>
        </div>

        <div className="form-group text-left">
          <label className="form-label">Confirm Password</label>
          <input
            type={showPassword ? 'text' : 'password'}
            className="form-input"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Confirm password"
          />
        </div>

        {error && <p className="form-error mb-16">{error}</p>}

        <button
          type="submit"
          className="btn btn-primary btn-full"
          disabled={loading || !password || !confirmPassword}
        >
          {loading ? 'Creating...' : 'Create Vault'}
        </button>
      </form>

      <div className="mt-24">
        <button
          type="button"
          className="btn btn-secondary btn-full"
          onClick={() => setImportMode(!importMode)}
        >
          {importMode ? 'Generate New Wallet' : 'Import Existing Wallet'}
        </button>
      </div>

      {importMode && (
        <div className="form-group text-left mt-16">
          <label className="form-label">Recovery Phrase</label>
          <textarea
            className="form-input"
            value={importMnemonic}
            onChange={(e) => setImportMnemonic(e.target.value)}
            placeholder="Enter your 12 or 24 word recovery phrase"
            rows={3}
            style={{ resize: 'none' }}
          />
          <p className="form-hint">
            Enter your BIP-39 recovery phrase, words separated by spaces.
          </p>
        </div>
      )}

      {error && (
        <div className="mt-16">
          <button
            type="button"
            className="btn btn-secondary btn-full"
            onClick={async () => {
              setLoading(true);
              setError(null);
              try {
                await chrome.runtime.sendMessage({ type: 'VAULT_RESET' });
                window.location.reload();
              } catch (err) {
                setError('Failed to reset vault');
              }
              setLoading(false);
            }}
            disabled={loading}
          >
            Reset Vault & Start Fresh
          </button>
        </div>
      )}
    </div>
  );

  // ===========================================================================
  // Render Mnemonic Step
  // ===========================================================================

  const renderMnemonicStep = () => (
    <div className="setup-container">
      <div className="setup-icon">📝</div>
      <h1 className="setup-title">Backup Your Recovery Phrase</h1>
      <p className="setup-description">
        Write down these words in order and store them safely.
        This is the only way to recover your wallet.
      </p>

      <div className="mnemonic-warning">
        <span className="mnemonic-warning-icon">⚠</span>
        <span className="mnemonic-warning-text">
          Never share your recovery phrase with anyone.
          Anyone with this phrase can access your funds.
        </span>
      </div>

      <div className="mnemonic-display">
        <div className="mnemonic-words">
          {mnemonic.map((word, index) => (
            <div key={index} className="mnemonic-word">
              <span className="mnemonic-word-number">{index + 1}.</span>
              {word}
            </div>
          ))}
        </div>
      </div>

      <button
        className="btn btn-primary btn-full"
        onClick={() => setStep('confirm')}
      >
        I've Written It Down
      </button>

      <button
        className="btn btn-secondary btn-full mt-8"
        onClick={() => {
          navigator.clipboard.writeText(mnemonic.join(' '));
        }}
      >
        Copy to Clipboard
      </button>
    </div>
  );

  // ===========================================================================
  // Render Confirm Step
  // ===========================================================================

  const renderConfirmStep = () => (
    <div className="setup-container">
      <div className="setup-icon">✅</div>
      <h1 className="setup-title">Setup Complete!</h1>
      <p className="setup-description">
        Your vault has been created successfully.
        {!importMode && ' Make sure you have backed up your recovery phrase.'}
      </p>

      <div className="card">
        <div className="detail-row">
          <span className="detail-label">Vault Status</span>
          <span className="detail-value">Unlocked</span>
        </div>
        <div className="detail-row">
          <span className="detail-label">Recovery Phrase</span>
          <span className="detail-value">{importMode ? 'Imported' : 'Generated'}</span>
        </div>
      </div>

      <button
        className="btn btn-primary btn-full"
        onClick={onComplete}
      >
        Start Using Certen Vault
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
      </header>

      <div className="content">
        {step === 'password' && renderPasswordStep()}
        {step === 'mnemonic' && renderMnemonicStep()}
        {step === 'confirm' && renderConfirmStep()}
      </div>

      <footer className="footer">
        Certen Protocol v1.0.0
      </footer>
    </div>
  );
};

export default Setup;
