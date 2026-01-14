# Certen Key Vault and Signer - Browser Extension Implementation Plan

## Executive Summary

This document provides a comprehensive implementation plan for a **minimalistic, security-focused browser extension** that serves as a Key Vault and Signer for the Certen Protocol. The extension focuses exclusively on key management and signing operations while delegating transaction construction to backend services.

**Core Principle**: Keys NEVER leave the extension. The web interface constructs transactions, the extension only signs.

---

## 1. Analysis Summary

### 1.1 Cryptographic Key Types Required

| Key Type | Algorithm | Usage | Library |
|----------|-----------|-------|---------|
| **ED25519** | EdDSA | Accumulate network (ADIs, data accounts, keypages, token transfers) | tweetnacl |
| **ECDSA secp256k1** | ECDSA | Ethereum/EVM transactions, Account Abstraction | @noble/secp256k1 |
| **BLS12-381** | BLS | Validator signature aggregation (future) | @noble/bls12-381 |

### 1.2 Current Security Issues Identified

| Issue | Location | Severity |
|-------|----------|----------|
| Private keys in `.env` file | `certen-protocol/.env` (72+ keys exposed) | CRITICAL |
| Plaintext localStorage storage | `AdiStorage.ts:13, 40` | CRITICAL |
| Hardcoded demo keys in source | `WalletInterface.tsx:121, 158` | CRITICAL |
| Simulated (fake) signatures | `CertenTransactionService.ts:273` | HIGH |
| No key encryption at rest | All key storage | HIGH |

### 1.3 Operations Requiring User Signatures

#### Accumulate Network (ED25519)
1. **ADI Creation** - `Signer.forLite(ed25519Key).sign(transaction)`
2. **Data Account Creation** - `Signer.forPage(keyPageUrl, key).sign(transaction)`
3. **Keypage Management** - Version-bound signing with `withVersion()`
4. **Token Transfers** - Signed envelopes to Accumulate network
5. **Account Authority Updates** - Multi-sig capable operations
6. **Credits Addition** - LID signer for ACME token accounts
7. **Transaction Intents** - ED25519 + SHA256 hash commitments

#### EVM Chains (ECDSA secp256k1)
1. **Smart Contract Calls** - CertenAnchorV3, CertenAccountV2
2. **Cross-chain Bridging** - Target chain execution
3. **Account Abstraction** - UserOp signing for EntryPoint

---

## 2. Architecture Design

### 2.1 Component Architecture

```
+------------------------------------------------------------------+
|                        WEB APPLICATION                            |
|  (wallet-interface, authority-editor, accumulate-bridge)          |
|                                                                   |
|  1. Constructs transaction via backend API                        |
|  2. Receives transaction hash                                     |
|  3. Calls window.certen.signTransaction(hash)                     |
+----------------------------------+-------------------------------+
                                   |
                                   v
+------------------------------------------------------------------+
|                      CONTENT SCRIPT                               |
|  - Injects window.certen provider into page                       |
|  - Routes requests to background via chrome.runtime               |
|  - Returns signatures to page                                     |
+----------------------------------+-------------------------------+
                                   |
                                   v
+------------------------------------------------------------------+
|                 BACKGROUND SERVICE WORKER                         |
|  - Message router for all RPC requests                           |
|  - Session management (vault lock/unlock)                         |
|  - Sign request queue management                                  |
|  - Triggers approval popup for signing operations                 |
+----------------------------------+-------------------------------+
                                   |
                                   v
+------------------------------------------------------------------+
|                     APPROVAL POPUP UI                             |
|  - Displays transaction details for user review                   |
|  - Key selection dropdown                                         |
|  - Approve / Reject buttons                                       |
|  - Password unlock if vault is locked                             |
+----------------------------------+-------------------------------+
                                   |
                                   v
+------------------------------------------------------------------+
|                       KEY VAULT MODULE                            |
|  - PBKDF2 key derivation (600K iterations)                        |
|  - AES-256-GCM encryption at rest                                 |
|  - ED25519 key generation and signing                             |
|  - ECDSA secp256k1 key generation and signing                     |
|  - chrome.storage.local for encrypted persistence                 |
+------------------------------------------------------------------+
```

### 2.2 Key Design Decisions

1. **Keys NEVER leave the extension** - All signing in service worker
2. **No transaction construction** - Extension only signs pre-computed hashes
3. **User approval for EVERY sign** - Popup-based approval flow
4. **Encrypted storage at rest** - AES-256-GCM with PBKDF2
5. **Manifest V3 compliant** - Service workers, no background pages
6. **Auto-lock timeout** - 15 minutes of inactivity

---

## 3. File Structure

```
certen-key-vault/
├── manifest.json                    # Extension manifest (Manifest V3)
├── package.json
├── tsconfig.json
├── webpack.config.js
│
├── src/
│   ├── background/
│   │   ├── index.ts                 # Service worker entry
│   │   ├── messageRouter.ts         # Routes messages from content script
│   │   ├── sessionManager.ts        # Vault unlock/lock session
│   │   └── signRequestQueue.ts      # Pending sign request queue
│   │
│   ├── vault/
│   │   ├── index.ts                 # Vault API exports
│   │   ├── crypto.ts                # PBKDF2, AES-256-GCM encryption
│   │   ├── keyStore.ts              # Encrypted key storage
│   │   ├── ed25519.ts               # ED25519 key generation/signing
│   │   ├── secp256k1.ts             # ECDSA secp256k1 for EVM
│   │   └── types.ts                 # Key types and interfaces
│   │
│   ├── content-script/
│   │   ├── index.ts                 # Content script entry
│   │   ├── provider.ts              # window.certen provider injection
│   │   └── messageHandler.ts        # Page <-> Extension communication
│   │
│   ├── popup/
│   │   ├── index.html               # Popup entry HTML
│   │   ├── index.tsx                # Popup React entry
│   │   ├── App.tsx                  # Main app component
│   │   ├── pages/
│   │   │   ├── Unlock.tsx           # Password unlock screen
│   │   │   ├── Setup.tsx            # Initial vault setup
│   │   │   ├── KeyList.tsx          # List of keys
│   │   │   ├── KeyGenerate.tsx      # Generate new key
│   │   │   ├── KeyImport.tsx        # Import existing key
│   │   │   ├── SignApproval.tsx     # Sign request approval
│   │   │   └── Settings.tsx         # Extension settings
│   │   └── components/
│   │       ├── KeyCard.tsx          # Individual key display
│   │       ├── TransactionDetails.tsx # Tx info for approval
│   │       └── PasswordInput.tsx    # Secure password field
│   │
│   ├── shared/
│   │   ├── constants.ts             # Shared constants
│   │   ├── types.ts                 # Shared type definitions
│   │   └── utils.ts                 # Utility functions
│   │
│   └── offscreen/
│       └── crypto-worker.ts         # Offscreen doc for heavy crypto
│
├── public/
│   ├── icons/                       # Extension icons (16, 32, 48, 128)
│   └── styles/                      # CSS files
│
└── tests/
    ├── vault/                       # Vault unit tests
    ├── signing/                     # Signing tests
    └── integration/                 # E2E tests
```

---

## 4. Key Management Implementation

### 4.1 Storage Schema

```typescript
// Encrypted vault structure stored in chrome.storage.local
interface EncryptedVaultData {
  version: number;                    // Schema version for migrations
  salt: string;                       // Base64 salt for PBKDF2
  iv: string;                         // Base64 IV for AES-GCM
  encryptedPayload: string;           // Base64 encrypted JSON
  kdfParams: {
    algorithm: 'pbkdf2';
    iterations: 600000;               // OWASP 2023 recommendation
  };
}

interface VaultPayload {
  keys: StoredKey[];
  metadata: {
    createdAt: number;
    lastModified: number;
  };
}

interface StoredKey {
  id: string;                         // UUID
  name: string;                       // User-assigned label
  type: 'ed25519' | 'secp256k1';
  publicKey: string;                  // Hex encoded
  privateKey: string;                 // Hex encoded (encrypted in vault)
  createdAt: number;
  lastUsedAt?: number;
  metadata: {
    accumulateUrl?: string;           // acc://... for ED25519
    evmAddress?: string;              // 0x... for secp256k1
    keyPageUrl?: string;              // Associated keypage
  };
}
```

### 4.2 Encryption Implementation

```typescript
// PBKDF2 key derivation
const PBKDF2_ITERATIONS = 600000;  // OWASP 2023 minimum
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;              // AES-256

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-512' },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// AES-256-GCM encryption
async function encrypt(data: string, key: CryptoKey): Promise<{iv: Uint8Array, ciphertext: Uint8Array}> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(data)
  );
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}
```

### 4.3 BIP-39 Mnemonic Support

```typescript
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';

// Generate new mnemonic (12 or 24 words)
function generateMnemonic(strength: 128 | 256 = 128): string {
  return bip39.generateMnemonic(wordlist, strength);
}

// Derive ED25519 key from mnemonic using SLIP-0010
function deriveED25519FromMnemonic(mnemonic: string, index: number = 0): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  path: string;
} {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  // SLIP-0010 path for ED25519: m/44'/540'/0'/0'/index'
  // 540 is the coin type for Accumulate
  const path = `m/44'/540'/0'/0'/${index}'`;
  const derived = HDKey.fromMasterSeed(seed).derive(path);
  const keyPair = nacl.sign.keyPair.fromSeed(derived.privateKey!);
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.secretKey,
    path
  };
}

// Derive secp256k1 key from mnemonic (standard BIP-44)
function deriveSecp256k1FromMnemonic(mnemonic: string, index: number = 0): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  path: string;
} {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  // BIP-44 path for Ethereum: m/44'/60'/0'/0/index
  const path = `m/44'/60'/0'/0/${index}`;
  const derived = HDKey.fromMasterSeed(seed).derive(path);
  const privateKey = derived.privateKey!;
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return { publicKey, privateKey, path };
}
```

### 4.4 ED25519 Implementation (Accumulate)

```typescript
import * as nacl from 'tweetnacl';

function generateED25519Key(): { publicKey: Uint8Array, privateKey: Uint8Array } {
  return nacl.sign.keyPair();
}

function signED25519(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return nacl.sign.detached(message, privateKey);
}

// Generate Accumulate Lite Account URL from public key
function generateLiteAccountUrl(publicKey: Uint8Array): string {
  const hash = sha256(publicKey);
  const keyHex = Buffer.from(hash.slice(0, 20)).toString('hex');
  const checksum = sha256(Buffer.from(keyHex, 'utf-8'));
  const checksumHex = Buffer.from(checksum.slice(28)).toString('hex');
  return `acc://${keyHex}${checksumHex}`;
}
```

### 4.4 ECDSA secp256k1 Implementation (EVM)

```typescript
import * as secp256k1 from '@noble/secp256k1';
import { keccak256 } from '@ethersproject/keccak256';

function generateSecp256k1Key(): { publicKey: Uint8Array, privateKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  return { publicKey, privateKey };
}

async function signSecp256k1(hash: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  const signature = secp256k1.sign(hash, privateKey, { lowS: true });
  // Return 65-byte signature: r (32) + s (32) + v (1)
  const sig = new Uint8Array(65);
  sig.set(signature.r, 0);
  sig.set(signature.s, 32);
  sig[64] = signature.recovery + 27;
  return sig;
}

function getEthAddress(publicKey: Uint8Array): string {
  const hash = keccak256(publicKey.slice(1)); // Remove 0x04 prefix
  return '0x' + hash.slice(-40);
}
```

---

## 5. window.certen Provider Interface

The extension must implement this interface exactly (already defined in wallet-interface):

```typescript
window.certen = {
  // Identity
  isCerten: true,
  isAccumulate: true,
  version: '1.0.0',

  // Connection
  connect(): Promise<{ accounts: any[]; connected: boolean }>,
  disconnect(): Promise<void>,
  isConnected(): boolean,
  getAccounts(): any[],
  getNetwork(): 'mainnet' | 'testnet' | 'devnet',

  // Signing (REQUIRES POPUP APPROVAL)
  signTransaction(txData: {
    principal: string;
    signer?: string;
    body: any;
  }): Promise<any>,

  signTransactionIntent(intentData: {
    adiUrl: string;
    transaction: any;
    signer: string;
    actionType?: string;
    description?: string;
  }): Promise<any>,

  // Operations (delegate to backend, sign result)
  sendTokens(from: string, to: string, amount: string): Promise<any>,
  addCredits(from: string, to: string, amount: number, oracle?: number): Promise<any>,

  // Query (read-only, no signing)
  queryAccount(url: string): Promise<any>,
  getBalance(accountUrl: string): Promise<string>,
  getCredits(accountUrl: string): Promise<number>,

  // Bridge
  bridgeToEVM(params: {
    sourceAccount: string;
    targetChain: string;
    targetAddress: string;
    amount: string;
  }): Promise<any>,
  getBridgeStatus(bridgeId: string): Promise<any>,

  // Events
  on(eventName: string, handler: (data: any) => void): void,
  off(eventName: string, handler: (data: any) => void): void,

  // Generic RPC
  request(args: { method: string; params?: any[] }): Promise<any>
};
```

---

## 6. Signing Flow

### 6.1 Complete Flow Diagram

```
1. Web App: window.certen.signTransaction({ transactionHash, signerUrl, ... })
           |
           v
2. Content Script: Receives request, generates requestId
           |
           v
3. Content Script: chrome.runtime.sendMessage({ type: 'SIGN_REQUEST', ... })
           |
           v
4. Background: Adds to signRequestQueue, opens approval popup
           |
           v
5. Popup: Displays transaction details, key selection
           |
           +---> User REJECTS --> Background returns error --> Web App receives rejection
           |
           v
6. User APPROVES with selected key
           |
           v
7. Background: Retrieves key from vault (must be unlocked)
           |
           v
8. Background: Performs ED25519 or secp256k1 signing
           |
           v
9. Background: Returns signature to Content Script
           |
           v
10. Content Script: Resolves Promise with signature
           |
           v
11. Web App: Receives { signature, publicKey, keyId }
```

### 6.2 Sign Request Types

| Method | Key Type | Data Required |
|--------|----------|---------------|
| `acc_signTransaction` | ED25519 | transactionHash, signerUrl, signerVersion |
| `acc_signHash` | ED25519 | hash (raw bytes) |
| `eth_signHash` | secp256k1 | hash, address |
| `eth_signTypedData` | secp256k1 | EIP-712 typed data |
| `certen_signIntent` | ED25519 | intentId, adiUrl, actionType |

### 6.3 Approval Popup UI

```typescript
// SignApproval.tsx - Key components
<div className="sign-approval">
  <header>
    <h2>Signature Request</h2>
    <span className="origin">{request.origin}</span>  {/* e.g., "localhost:3001" */}
  </header>

  <TransactionDetails>
    <div>Action: {humanReadable.action}</div>        {/* "Send 100 ACME" */}
    <div>From: {humanReadable.from}</div>            {/* "acc://my-adi.acme/tokens" */}
    <div>To: {humanReadable.to}</div>                {/* "acc://recipient.acme" */}
    <div>Hash: {truncate(transactionHash)}</div>     {/* "a1b2c3...x7y8z9" */}
  </TransactionDetails>

  <KeySelector
    keys={availableKeys}
    selectedKey={selectedKeyId}
    filterType={request.keyType}                     {/* "ed25519" or "secp256k1" */}
  />

  <div className="actions">
    <button onClick={reject}>Reject</button>
    <button onClick={approve} disabled={!selectedKeyId}>Sign</button>
  </div>
</div>
```

---

## 7. Security Implementation

### 7.1 Threat Model and Mitigations

| Threat | Mitigation |
|--------|------------|
| Malicious website requests signature | Popup approval required, origin displayed |
| XSS in extension | CSP in manifest, no inline scripts |
| Key extraction from storage | AES-256-GCM encryption with PBKDF2 |
| Password brute force | 600K PBKDF2 iterations |
| Memory dump attack | Clear secrets after use, service worker lifecycle |
| Phishing popup | Always show request origin prominently |
| Replay attacks | Accumulate uses microsecond timestamps |

### 7.2 Security Checklist

- [ ] All crypto via Web Crypto API (native, audited)
- [ ] Private keys never logged/serialized
- [ ] Passwords cleared from memory after derivation
- [ ] CSP prevents inline script execution
- [ ] No `eval()` or `Function()` constructors
- [ ] All storage encrypted, no plaintext keys
- [ ] Origin validation on all incoming messages
- [ ] 15-minute auto-lock timeout
- [ ] Rate limiting on password attempts

### 7.3 Content Security Policy (manifest.json)

```json
{
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'"
  }
}
```

---

## 8. Integration Points

### 8.1 No Changes Required to Web Interfaces

The existing `WalletConnectionService.ts` already implements the `window.certen` interface correctly. Once the extension is installed, the web interfaces will automatically detect and use it.

### 8.2 Backend Communication Pattern

```typescript
// Web interface flow (unchanged):

// 1. Web constructs transaction via backend API
const response = await fetch('/api/v1/intent/create', {
  method: 'POST',
  body: JSON.stringify({ adiUrl, amount, recipient, ... })
});
const { transactionHash } = await response.json();

// 2. Web requests signature from extension
const { signature, publicKey } = await window.certen.signTransaction({
  transactionHash,
  signerUrl: 'acc://my-adi.acme/book/1',
  signerVersion: 1,
  humanReadable: { action: 'Send Tokens', amount: '100 ACME' }
});

// 3. Web submits signed transaction via backend
await fetch('/api/v1/transaction/submit', {
  method: 'POST',
  body: JSON.stringify({ transactionHash, signature, publicKey })
});
```

---

## 9. Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Extension Framework | Manifest V3 | Chrome/Edge/Firefox, modern standard |
| Language | TypeScript 5.x | Type safety, IDE support |
| UI Framework | React 18 | Component-based, existing patterns |
| Build Tool | Webpack 5 | Extension bundling, code splitting |
| Crypto - KDF | Web Crypto PBKDF2 | Browser native, audited |
| Crypto - Encryption | Web Crypto AES-GCM | Authenticated encryption |
| Crypto - ED25519 | tweetnacl | Same as accumulate.js |
| Crypto - secp256k1 | @noble/secp256k1 | Same as accumulate.js |
| Crypto - BIP39/BIP32 | @scure/bip39, @scure/bip32 | HD key derivation from mnemonic |
| Storage | chrome.storage.local | Extension API, 10MB limit |
| Testing | Jest + React Testing Library | Standard tooling |

---

## 10. Implementation Phases

### Phase 1: Core Vault (Week 1-2)
- [ ] Project setup (Manifest V3, Webpack, TypeScript)
- [ ] Vault encryption/decryption (PBKDF2 + AES-GCM)
- [ ] Key generation (ED25519, secp256k1)
- [ ] chrome.storage.local integration
- [ ] Basic popup UI (setup, unlock, key list)

### Phase 2: Signing Flow (Week 3-4)
- [ ] Content script with window.certen provider
- [ ] Background service worker message routing
- [ ] Sign request queue management
- [ ] Approval popup UI with transaction details
- [ ] ED25519 signing for Accumulate
- [ ] secp256k1 signing for EVM

### Phase 3: Full Interface (Week 5-6)
- [ ] Complete window.certen API implementation
- [ ] BIP-39 mnemonic generation and recovery (12/24 words)
- [ ] Key import functionality (hex private key, mnemonic phrase)
- [ ] HD key derivation (SLIP-0010 for ED25519, BIP-44 for secp256k1)
- [ ] Network selection (devnet, testnet, mainnet)
- [ ] Event system (accountsChanged, networkChanged)
- [ ] Settings page (auto-lock timeout, etc.)

### Phase 4: Testing & Polish (Week 7-8)
- [ ] Unit tests for vault and signing
- [ ] Integration tests with wallet-interface
- [ ] Security audit preparation
- [ ] Documentation
- [ ] Chrome Web Store submission preparation

---

## 11. Migration from Hardcoded Keys

### 11.1 For Developers
1. Remove private keys from `.env` file
2. Store only **public** configuration (contract addresses, RPC URLs)
3. Update backend to accept signatures from extension
4. Remove simulated signature code

### 11.2 For Users
1. Install Certen Key Vault extension
2. Create new vault with secure password
3. Generate new keys OR import existing keys
4. Connect to wallet-interface via extension
5. All future signing happens in extension

### 11.3 Deprecation Path
```typescript
// Old code (REMOVE):
const privateKey = process.env.ACCUMULATE_PRIVATE_KEY;
const signature = await signer.sign(transaction);

// New code:
const { signature } = await window.certen.signTransaction({
  transactionHash,
  signerUrl,
  humanReadable: { action: 'Send Tokens', ... }
});
```

---

## 12. Verification Plan

### 12.1 Manual Testing
1. Install extension in Chrome/Firefox
2. Open wallet-interface at `localhost:3001`
3. Click "Connect Certen Wallet"
4. Verify extension popup appears
5. Generate or import test key
6. Initiate transaction
7. Verify approval popup shows correct details
8. Approve and verify signature returned

### 12.2 Automated Tests
```bash
# Run unit tests
npm test

# Run integration tests
npm run test:integration

# Run E2E tests with Playwright
npm run test:e2e
```

### 12.3 Security Audit Points
- Encryption strength (PBKDF2 iterations, AES-GCM)
- Key never in logs or console
- Origin validation in message handling
- CSP effectiveness
- Memory handling after unlock

---

## 13. References

### Critical Files in Codebase
1. `certen-protocol/web/wallet-interface/src/services/WalletConnectionService.ts` - Consumer of window.certen
2. `certen-protocol/services/accumulate-bridge/src/AccumulateService.ts` - Transaction construction patterns
3. `certen-protocol/.env` - Keys to be removed after migration

### External Dependencies
- [tweetnacl](https://github.com/dchest/tweetnacl-js) - ED25519 implementation
- [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) - ECDSA implementation
- [Chrome Extension Manifest V3](https://developer.chrome.com/docs/extensions/mv3/intro/)

---

## 14. Success Criteria

1. **Security**: No private keys stored outside encrypted vault
2. **Usability**: User can sign transactions with 2 clicks (open popup, approve)
3. **Compatibility**: Works with existing wallet-interface without changes
4. **Performance**: Signing completes in < 100ms
5. **Reliability**: 99.9% success rate for signing operations
