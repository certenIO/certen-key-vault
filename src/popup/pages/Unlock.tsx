/**
 * Certen Key Vault - Unlock Page
 *
 * Password entry to unlock the vault.
 */

import React, { useState } from 'react';

// =============================================================================
// Types
// =============================================================================

interface UnlockProps {
  onUnlock: () => void;
}

// =============================================================================
// Unlock Component
// =============================================================================

const Unlock: React.FC<UnlockProps> = ({ onUnlock }) => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'VAULT_UNLOCK',
        password
      });

      if (response.success) {
        onUnlock();
      } else {
        setError(response.error || 'Invalid password');
      }
    } catch (err) {
      setError('Failed to unlock vault');
      console.error(err);
    }

    setLoading(false);
  };

  return (
    <div className="app-container">
      <header className="header">
        <div className="header-title">
          <span>🔒</span>
          <h1>Certen Key Vault</h1>
        </div>
      </header>

      <div className="content">
        <div className="setup-container">
          <div className="setup-icon">🔒</div>
          <h1 className="setup-title">Vault Locked</h1>
          <p className="setup-description">
            Enter your password to unlock your vault.
          </p>

          <form onSubmit={handleSubmit}>
            <div className="form-group text-left">
              <label className="form-label">Password</label>
              <div className="password-input-wrapper">
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="form-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
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

            {error && <p className="form-error mb-16">{error}</p>}

            <button
              type="submit"
              className="btn btn-primary btn-full"
              disabled={loading || !password}
            >
              {loading ? 'Unlocking...' : 'Unlock'}
            </button>
          </form>
        </div>
      </div>

      <footer className="footer">
        Certen Protocol v1.0.0
      </footer>
    </div>
  );
};

export default Unlock;
