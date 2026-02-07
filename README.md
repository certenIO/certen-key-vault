# Certen Key Vault

Chrome browser extension for secure key management and transaction signing across Accumulate and EVM blockchains within the Certen Protocol ecosystem.

## Overview

The Certen Key Vault is a Manifest V3 browser extension that provides client-side key storage, multi-curve cryptographic signing, and a user-controlled approval interface for blockchain transactions. Private keys are encrypted at rest using AES-256-GCM with PBKDF2 key derivation, and all signing operations require explicit user approval via a popup interface.

Key capabilities:

1. **Encrypted Key Storage**: AES-256-GCM vault with PBKDF2-SHA512 key derivation (600,000 iterations)
2. **Multi-Curve Support**: Ed25519 (Accumulate, Solana, Aptos, Sui), secp256k1 (Ethereum, TRON, Cosmos), and BLS12-381 (validator consensus)
3. **HD Wallet**: BIP-39 mnemonic generation with BIP-44/SLIP-0010 hierarchical key derivation
4. **Transaction Signing**: User-approved signing for Accumulate transactions, Ethereum hashes, EIP-191/EIP-712 messages, and cross-chain intents
5. **Multi-Chain Addresses**: Automatic address derivation for Ethereum, Solana, Cosmos, Aptos, Sui, TRON, TON, and NEAR
6. **Two-Phase Signing**: Prepare/approve pattern for integration with the Certen web application

## Architecture

```
+------------------------------------------------------------------+
|                     Web Application                               |
+------------------------------------------------------------------+
|  window.certen provider (injected by content script)              |
+------------------------------------------------------------------+
         |  postMessage                      |  postMessage
         v                                   v
+------------------------------------------------------------------+
|                     Content Script                                |
|  Relays messages between page context and service worker          |
+------------------------------------------------------------------+
         |  chrome.runtime.sendMessage       |
         v                                   v
+------------------------------------------------------------------+
|                  Background Service Worker                        |
+------------------------------------------------------------------+
|                                                                    |
|  +------------------+    +------------------+    +---------------+ |
|  |   Message        |    |   Sign Request   |    |  Key Store    | |
|  |   Router         |--->|   Queue          |--->|  (Encrypted)  | |
|  +------------------+    +------------------+    +---------------+ |
|          |                       |                      |         |
|          v                       v                      v         |
|  +------------------+    +------------------+    +---------------+ |
|  |   Popup UI       |    |   Crypto Layer   |    |  chrome.      | |
|  |   (React)        |    |   (Ed25519,      |    |  storage      | |
|  |                  |    |    secp256k1,     |    |  .local       | |
|  |                  |    |    BLS12-381)     |    |               | |
|  +------------------+    +------------------+    +---------------+ |
|                                                                    |
+------------------------------------------------------------------+
```

## Features

- **Password-Protected Vault**: Master password encrypts all key material
- **Key Generation**: Random key generation for Ed25519, secp256k1, and BLS12-381
- **Mnemonic Backup**: BIP-39 (12 or 24 word) seed phrase with deterministic key derivation
- **Key Import**: Import existing private keys or recover from mnemonic phrases
- **Signing Approval**: Visual popup showing transaction details, requesting origin, and key selection
- **Auto-Lock**: Vault locks after 15 minutes of inactivity
- **CREATE2 Prediction**: EVM account abstraction address prediction for ERC-4337 accounts
- **Network Selection**: DevNet, Kermit Testnet, and Mainnet support
- **Accumulate Lite Accounts**: Automatic lite account URL derivation from Ed25519 public keys

## Prerequisites

- Google Chrome or Chromium-based browser
- Node.js 18+ (for building from source)

## Quick Start

```bash
# Clone repository
git clone https://github.com/certenIO/key-vault-signer.git
cd key-vault-signer

# Install dependencies
npm install

# Build the extension
npm run build

# Load in Chrome:
# 1. Navigate to chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the dist/ directory
```

## Installation

### Build from Source

```bash
# Install dependencies
npm install

# Production build
npm run build

# Development build (with source maps)
npm run build:dev

# Watch mode (rebuilds on changes)
npm run dev
```

### Output Structure

```
dist/
├── manifest.json          # Extension manifest
├── background.js          # Service worker
├── content-script.js      # Content script
├── inpage.js             # Injected page provider
├── popup.js              # React popup application
├── popup.html            # Popup HTML shell
└── public/
    └── icons/            # Extension icons (16, 32, 48, 128px)
```

## Configuration

### Networks

| Network | Accumulate Endpoint | Ethereum Endpoint |
|---------|--------------------|--------------------|
| DevNet | `http://localhost:26660` | - |
| Testnet | `https://kermit.accumulatenetwork.io` | Sepolia |
| Mainnet | `https://mainnet.accumulatenetwork.io` | Ethereum Mainnet |

### Cryptographic Parameters

| Parameter | Value | Standard |
|-----------|-------|----------|
| Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Derivation | PBKDF2-SHA512 | RFC 8018 |
| KDF Iterations | 600,000 | OWASP 2023 |
| Salt Length | 256 bits | - |
| IV Length | 96 bits | GCM standard |
| Key Length | 256 bits | - |
| Auto-Lock Timeout | 15 minutes | - |

### Derivation Paths

| Curve | Path | Standard |
|-------|------|----------|
| Ed25519 | `m/44'/540'/0'/0'/0'` | SLIP-0010 (all hardened) |
| secp256k1 | `m/44'/60'/0'/0/0` | BIP-44 |
| BLS12-381 | `m/12381/60/0/0` | EIP-2333 |

## Web Application Integration

### Provider API

The extension injects a `window.certen` provider into web pages with the following methods:

#### Connection

```typescript
// Connect to the extension
const { accounts, connected } = await window.certen.connect();

// Disconnect
await window.certen.disconnect();

// Check connection status
const isConnected = window.certen.isConnected();
```

#### Signing

```typescript
// Sign an Accumulate transaction
const { signature, publicKey } = await window.certen.signTransaction({
  principal: "acc://my-adi.acme/tokens",
  transactionHash: "0x...",
  humanReadable: { type: "Send Tokens", amount: "100 ACME" }
});

// Sign a hash
const { signature, publicKey } = await window.certen.signHash({
  hash: "0x...",
  keyType: "ed25519"
});

// Sign a pending multi-sig transaction
const result = await window.certen.signPendingTransaction({
  transactionHash: "0x...",
  signer: "acc://my-adi.acme/book/1",
  signerVersion: 1,
  timestamp: Date.now() * 1000
});

// Sign an Ethereum personal message (EIP-191)
const { signature, publicKey } = await window.certen.signPersonalMessage(
  "Message to sign",
  "0xYourAddress"
);
```

#### Key Selection

```typescript
// Prompt user to select a key
const {
  publicKey,
  publicKeyHash,
  keyId,
  keyName,
  keyType,
  accumulateUrl,
  evmAddress
} = await window.certen.selectKey({
  keyType: "ed25519",
  purpose: "Select a key for ADI creation"
});

// Update key metadata (e.g., associate a key page)
await window.certen.updateKeyMetadata({
  publicKey: "hex...",
  metadata: { keyPageUrl: "acc://my-adi.acme/book/1" }
});
```

#### Account Queries

```typescript
// Query an Accumulate account
const account = await window.certen.queryAccount("acc://my-adi.acme");

// Get token balance
const balance = await window.certen.getBalance("acc://my-adi.acme/tokens");

// Get credit balance
const credits = await window.certen.getCredits("acc://my-adi.acme/book/1");
```

### Supported Sign Request Types

| Type | Description |
|------|-------------|
| `acc_signTransaction` | Accumulate transaction signing |
| `acc_signPendingTransaction` | Multi-sig pending transaction signing |
| `acc_signHash` | Generic Accumulate hash signing |
| `eth_signHash` | Ethereum hash signing |
| `eth_signTypedData` | EIP-712 typed data signing |
| `eth_signPersonalMessage` | EIP-191 personal message signing |
| `certen_signIntent` | Cross-chain intent signing |
| `bls_signHash` | BLS consensus signature |

## Address Derivation

The extension generates addresses for multiple blockchains from a single key:

### Ed25519 Keys

| Chain | Format | Algorithm |
|-------|--------|-----------|
| Accumulate | `acc://{hash}{checksum}` | SHA-256, first 20 bytes + 4-byte checksum |
| Solana | Base58 | Base58(public key) |
| Aptos | `0x...` | SHA3-256(public key + 0x00) |
| Sui | `0x...` | Blake2b-256(flag byte + public key) |
| TON | `0:...` | SHA-256(workchain + public key) |
| NEAR | Hex | Hex(public key) |

### secp256k1 Keys

| Chain | Format | Algorithm |
|-------|--------|-----------|
| Ethereum | `0x...` | Keccak-256, last 20 bytes |
| TRON | Base58Check | RIPEMD-160(SHA-256(pubkey)) + 0x41 prefix |
| Cosmos | `cosmos1...` | Bech32(RIPEMD-160(SHA-256(compressed pubkey))) |

## Background Message Protocol

### Vault Operations

| Message Type | Direction | Description |
|--------------|-----------|-------------|
| `VAULT_STATUS` | App -> BG | Query vault initialization and lock status |
| `VAULT_INITIALIZE` | App -> BG | Create new vault with password |
| `VAULT_UNLOCK` | App -> BG | Unlock vault with password |
| `VAULT_LOCK` | App -> BG | Lock vault and clear memory |
| `VAULT_RESET` | App -> BG | Clear all stored data |

### Key Operations

| Message Type | Direction | Description |
|--------------|-----------|-------------|
| `GET_KEYS` | App -> BG | List all keys (vault must be unlocked) |
| `GENERATE_KEY` | App -> BG | Create new random key |
| `DERIVE_KEY` | App -> BG | Derive key from vault mnemonic |
| `IMPORT_KEY` | App -> BG | Import private key (hex) |
| `IMPORT_MNEMONIC` | App -> BG | Import key from custom mnemonic |
| `REMOVE_KEY` | App -> BG | Delete a key |
| `UPDATE_KEY_METADATA` | App -> BG | Update key metadata |

### Signing Operations

| Message Type | Direction | Description |
|--------------|-----------|-------------|
| `CERTEN_RPC_REQUEST` | Content -> BG | Forward RPC method from web app |
| `GET_PENDING_SIGN_REQUEST` | Popup -> BG | Get next pending signing request |
| `APPROVE_SIGN_REQUEST` | Popup -> BG | User approved signing |
| `REJECT_SIGN_REQUEST` | Popup -> BG | User rejected signing |

### Key Selection

| Message Type | Direction | Description |
|--------------|-----------|-------------|
| `GET_PENDING_KEY_SELECTION` | Popup -> BG | Get pending key selection request |
| `COMPLETE_KEY_SELECTION` | Popup -> BG | User selected a key |
| `REJECT_KEY_SELECTION` | Popup -> BG | User rejected key selection |

## Project Structure

```
key-vault-signer/
├── src/
│   ├── background/
│   │   ├── index.ts              # Service worker entry point
│   │   ├── messageRouter.ts      # RPC routing and vault operations
│   │   └── signRequestQueue.ts   # Pending signature request management
│   ├── content-script/
│   │   ├── index.ts              # Content script message relay
│   │   └── inpage.ts             # window.certen provider injection
│   ├── popup/
│   │   ├── App.tsx               # Main React component with mode routing
│   │   ├── index.tsx             # React entry point
│   │   ├── index.html            # Popup HTML template
│   │   ├── styles.css            # UI styling
│   │   └── pages/
│   │       ├── Setup.tsx         # Vault creation and mnemonic backup
│   │       ├── Unlock.tsx        # Password entry interface
│   │       ├── SignApproval.tsx   # Transaction signing approval
│   │       └── KeySelection.tsx  # Key picker for external requests
│   ├── vault/
│   │   ├── keyStore.ts           # Encrypted storage and session management
│   │   ├── crypto.ts             # PBKDF2, AES-256-GCM encryption
│   │   ├── ed25519.ts            # Ed25519 signing and lite account URLs
│   │   ├── secp256k1.ts          # secp256k1 signing and Ethereum addresses
│   │   ├── bls12381.ts           # BLS12-381 validator key operations
│   │   ├── mnemonic.ts           # BIP-39 mnemonics and HD derivation
│   │   ├── addresses.ts          # Multi-chain address derivation
│   │   ├── create2.ts            # EVM CREATE2 address prediction
│   │   └── index.ts              # Module exports
│   ├── shared/
│   │   ├── types.ts              # TypeScript interfaces and type definitions
│   │   └── constants.ts          # Crypto parameters and network configuration
│   └── config/
│       └── contracts.ts          # EVM contract addresses by chain ID
├── public/
│   └── icons/                    # Extension icons (PNG, multiple sizes)
├── manifest.json                 # Chrome Extension Manifest V3
├── webpack.config.js             # Build configuration (4 entry points)
├── package.json                  # Dependencies and scripts
├── tsconfig.json                 # TypeScript configuration
└── jest.config.js                # Test configuration
```

## Development

### Build Commands

```bash
# Production build with icon generation
npm run build

# Development build with source maps
npm run build:dev

# Watch mode (auto-rebuild on changes)
npm run dev

# Regenerate icons from SVG source
npm run icons

# Clean build artifacts
npm run clean
```

### Running Tests

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch

# Linting
npm run lint
```

### Webpack Entry Points

| Entry | Source | Output | Purpose |
|-------|--------|--------|---------|
| background | `src/background/index.ts` | `background.js` | Service worker |
| content-script | `src/content-script/index.ts` | `content-script.js` | Page-to-extension relay |
| inpage | `src/content-script/inpage.ts` | `inpage.js` | `window.certen` provider |
| popup | `src/popup/index.tsx` | `popup.js` | React popup UI |

## Security Considerations

### Encryption at Rest

All private keys are encrypted using AES-256-GCM before being written to `chrome.storage.local`. The encryption key is derived from the user's password via PBKDF2-SHA512 with 600,000 iterations and a 256-bit random salt. The derived key is never stored -- it is recomputed from the password on each unlock.

### Session Management

- Vault locks automatically after 15 minutes of inactivity
- Service worker restart forces a vault lock (Chrome behavior)
- Decrypted key material is cleared from memory on lock via secure wipe
- Connection state is held in memory only and is not persisted

### Content Security Policy

```
script-src 'self'; object-src 'self'
```

Only extension-bundled scripts execute. No inline scripts, no `eval()`, no remote code loading.

### Signing Authorization

- Every signing operation opens a popup for explicit user approval
- The requesting website origin is displayed alongside transaction details
- Pending sign requests time out after 5 minutes
- Users select which key to use for each signing operation

### Key Isolation

- Private keys never leave the extension context
- The web application receives only signatures and public keys
- No private key data is transmitted over `chrome.runtime.sendMessage`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Extension not detected | Verify extension is enabled in `chrome://extensions/` |
| `window.certen` undefined | Refresh the page after installing the extension |
| Vault locked unexpectedly | Service worker restarted; re-enter password |
| Signing popup not appearing | Check if popup is blocked; try clicking the extension icon |
| Key not found for signing | Ensure the correct key type (Ed25519/secp256k1) is available |
| Connection lost on refresh | Expected behavior; call `connect()` again |

## Related Components

| Component | Repository | Description |
|-----------|------------|-------------|
| Web App | `certen-web-app` | React SPA that consumes the `window.certen` provider |
| API Bridge | `api-bridge` | Constructs transactions for two-phase signing |
| Pending Service | `certen-pending-service` | Discovers multi-sig transactions needing signatures |
| Smart Contracts | `certen-contracts` | ERC-4337 account abstraction and anchor contracts |

## License

MIT License

Copyright 2025 Certen Protocol. All rights reserved.
