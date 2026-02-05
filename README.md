# Certen Key Vault

Chrome browser extension for secure key management and transaction signing in the Certen Protocol ecosystem.

## Overview

Certen Key Vault is a Manifest V3 Chrome extension that generates, stores, and signs with cryptographic keys for Accumulate and Ethereum blockchains. Keys are encrypted at rest using PBKDF2 key derivation and AES-256-GCM authenticated encryption, with automatic vault locking after inactivity.

The extension communicates with web applications through a secure message-passing protocol, enabling two-phase transaction signing where the web app constructs the transaction and the extension signs it without exposing private keys.

Key features:

1. **Secure Storage**: Keys encrypted with PBKDF2 (600K iterations) + AES-256-GCM
2. **Multi-Curve Support**: ED25519 (Accumulate), secp256k1 (Ethereum), BLS12-381 (validators)
3. **Auto-Lock**: Vault locks automatically after configurable inactivity period
4. **Sign Request Queue**: Pending signature requests tracked with badge notifications

## Architecture

```
+------------------------------------------------------------------+
|                        Certen Key Vault                           |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------+    +------------------+    +---------------+ |
|  |   Popup UI       |    |   Background     |    |  Key Store    | |
|  |   (React)        |<-->|   Service Worker |<-->|  (Encrypted)  | |
|  +------------------+    +------------------+    +---------------+ |
|                                 |                                 |
|                                 v                                 |
|                          +-------------+                          |
|                          |   Message   |                          |
|                          |   Router    |                          |
|                          +-------------+                          |
|                                 |                                 |
+------------------------------------------------------------------+
                                  |
                                  v
+------------------------------------------------------------------+
|                     Web Application (via Content Script)          |
+------------------------------------------------------------------+
|  - Sends sign requests                                            |
|  - Receives signatures                                            |
|  - Queries available keys                                         |
+------------------------------------------------------------------+
```

## Security Model

### Encryption

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | PBKDF2-SHA512 | 600,000 iterations (OWASP 2023) |
| Encryption | AES-256-GCM | 256-bit key, 96-bit IV |
| Salt | CSPRNG | 256 bits |

### Key Storage

- Private keys never leave the extension
- Keys encrypted before storage in `chrome.storage.local`
- Decryption key derived from user password, not stored
- Vault auto-locks after timeout (default: 15 minutes)
- Memory cleared on lock

### Message Protocol

Web applications communicate via `chrome.runtime.sendMessage`:

```typescript
// Request signature
{
  type: 'SIGN_REQUEST',
  payload: {
    hashHex: '0x...',      // Transaction hash to sign
    keyId: 'key-uuid',     // Key to sign with
    origin: 'app.example'  // Requesting origin
  }
}

// Response
{
  success: true,
  signature: '0x...'       // 64-byte ED25519 signature
}
```

## Supported Key Types

| Type | Curve | Use Case | Signature Size |
|------|-------|----------|----------------|
| ED25519 | Curve25519 | Accumulate transactions | 64 bytes |
| secp256k1 | secp256k1 | Ethereum transactions | 64 bytes + recovery |
| BLS12-381 | BLS12-381 | Validator consensus | 96 bytes |

## Prerequisites

- Chrome 102+ (Manifest V3 support)
- Node.js 18+ (for building)

## Installation

### From Chrome Web Store

Coming soon.

### From Source (Development)

```bash
# Clone repository
git clone https://github.com/certenIO/key-vault-signer.git
cd key-vault-signer

# Install dependencies
npm install

# Build extension
npm run build

# Load in Chrome:
# 1. Open chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the `dist/` folder
```

### Development Mode

```bash
# Build with watch mode
npm run dev

# Rebuild icons
npm run icons

# Run tests
npm test
```

## Configuration

The extension uses the following defaults:

| Setting | Default | Description |
|---------|---------|-------------|
| Auto-lock timeout | 15 minutes | Lock after inactivity |
| PBKDF2 iterations | 600,000 | Key derivation rounds |
| Salt length | 32 bytes | Random salt per vault |
| IV length | 12 bytes | AES-GCM nonce |

## Project Structure

```
key-vault-signer/
├── src/
│   ├── background/
│   │   ├── index.ts              # Service worker entry
│   │   ├── messageRouter.ts      # Message handling
│   │   └── signRequestQueue.ts   # Pending requests
│   ├── content-script/
│   │   ├── index.ts              # Content script
│   │   └── inpage.ts             # Injected page script
│   ├── popup/
│   │   ├── App.tsx               # Popup React app
│   │   ├── pages/                # Popup pages
│   │   └── components/           # UI components
│   ├── vault/
│   │   ├── crypto.ts             # PBKDF2, AES-GCM
│   │   ├── keyStore.ts           # Key storage manager
│   │   ├── ed25519.ts            # ED25519 operations
│   │   ├── secp256k1.ts          # secp256k1 operations
│   │   ├── bls12381.ts           # BLS12-381 operations
│   │   ├── mnemonic.ts           # BIP39 seed phrases
│   │   └── create2.ts            # CREATE2 address derivation
│   ├── shared/
│   │   └── constants.ts          # Shared constants
│   └── config/
│       └── contracts.ts          # Contract addresses
├── public/
│   ├── popup.html                # Popup HTML
│   └── icons/                    # Extension icons
├── manifest.json                 # Extension manifest
├── webpack.config.js
├── package.json
└── tsconfig.json
```

## API Reference

### Vault Operations

| Message Type | Description | Parameters |
|--------------|-------------|------------|
| `VAULT_INIT` | Create new vault | `password` |
| `VAULT_UNLOCK` | Unlock vault | `password` |
| `VAULT_LOCK` | Lock vault | - |
| `VAULT_STATUS` | Get lock status | - |
| `VAULT_CHANGE_PASSWORD` | Change password | `oldPassword`, `newPassword` |

### Key Operations

| Message Type | Description | Parameters |
|--------------|-------------|------------|
| `KEY_GENERATE` | Generate new key | `type`, `name` |
| `KEY_IMPORT` | Import private key | `type`, `privateKeyHex`, `name` |
| `KEY_LIST` | List all keys | - |
| `KEY_DELETE` | Delete a key | `keyId` |
| `KEY_EXPORT` | Export public key | `keyId` |

### Signing Operations

| Message Type | Description | Parameters |
|--------------|-------------|------------|
| `SIGN_REQUEST` | Request signature | `hashHex`, `keyId` |
| `SIGN_APPROVE` | Approve pending | `requestId` |
| `SIGN_REJECT` | Reject pending | `requestId` |
| `SIGN_PENDING_LIST` | List pending | - |

## Development

### Building

```bash
# Production build
npm run build

# Development build with watch
npm run dev

# Generate icons from SVG
npm run icons
```

### Testing

```bash
# Run tests
npm test

# Watch mode
npm run test:watch
```

### Linting

```bash
npm run lint
```

### Clean Build

```bash
npm run clean
npm run build
```

## Web App Integration

### Detecting Extension

```typescript
function isKeyVaultInstalled(): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        EXTENSION_ID,
        { type: 'VAULT_STATUS' },
        (response) => {
          resolve(!chrome.runtime.lastError && response?.installed);
        }
      );
    } catch {
      resolve(false);
    }
  });
}
```

### Requesting Signature

```typescript
async function requestSignature(hashHex: string, keyId: string): Promise<string> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      EXTENSION_ID,
      {
        type: 'SIGN_REQUEST',
        payload: { hashHex, keyId }
      },
      (response) => {
        if (response?.success) {
          resolve(response.signature);
        } else {
          reject(new Error(response?.error || 'Signing failed'));
        }
      }
    );
  });
}
```

### Listing Available Keys

```typescript
async function listKeys(): Promise<KeyInfo[]> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      EXTENSION_ID,
      { type: 'KEY_LIST' },
      (response) => {
        if (response?.success) {
          resolve(response.keys);
        } else {
          reject(new Error(response?.error || 'Failed to list keys'));
        }
      }
    );
  });
}
```

## Security Considerations

### What the Extension Does

- Generates cryptographic keys using Web Crypto API
- Stores encrypted keys in `chrome.storage.local`
- Signs transaction hashes when user approves
- Auto-locks after inactivity timeout

### What the Extension Does NOT Do

- Store unencrypted private keys
- Transmit private keys to web apps or servers
- Sign without user confirmation (pending requests require approval)
- Access keys from other extensions

### Best Practices

1. Use a strong, unique password for the vault
2. Review sign requests before approving
3. Keep the extension updated
4. Do not share your password or export private keys

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Extension not detected | Reload web app, check extension is enabled |
| Signing fails | Ensure vault is unlocked, key exists |
| Auto-lock too fast | Adjust timeout in settings |
| Keys not showing | Check vault is unlocked |

## Related Components

| Component | Repository | Description |
|-----------|------------|-------------|
| Web App | `certen-web-app` | React SPA that uses Key Vault |
| API Bridge | `api-bridge` | Transaction construction |
| Pending Service | `certen-pending-service` | Multi-sig discovery |

## License

MIT License

Copyright 2025 Certen Protocol. All rights reserved.
