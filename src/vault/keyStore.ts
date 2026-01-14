/**
 * Certen Key Vault - Key Store
 *
 * Manages encrypted storage of keys using chrome.storage.local.
 * Features:
 * - Password-protected vault with PBKDF2 key derivation
 * - AES-256-GCM encryption at rest
 * - Auto-lock timeout
 * - Session management
 */

import {
  EncryptedVaultData,
  VaultPayload,
  VaultMetadata,
  StoredKey,
  KeyType,
  KeyMetadata
} from '../shared/types';

import {
  deriveKey,
  encrypt,
  decrypt,
  generateSalt,
  generateUUID,
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  PBKDF2_ITERATIONS
} from './crypto';

import { generateED25519Key, ed25519FromPrivateKey, generateLiteAccountUrl, getPublicKeyHash } from './ed25519';
import { generateSecp256k1Key, secp256k1FromPrivateKeyHex, getEthAddress } from './secp256k1';
import {
  generateMnemonic,
  validateMnemonic,
  deriveED25519FromMnemonic,
  deriveSecp256k1FromMnemonic
} from './mnemonic';

// =============================================================================
// Constants
// =============================================================================

const STORAGE_KEY = 'certen_vault_v1';
const DEFAULT_AUTO_LOCK_TIMEOUT = 15 * 60 * 1000; // 15 minutes

// =============================================================================
// KeyStore Class
// =============================================================================

export class KeyStore {
  private derivedKey: CryptoKey | null = null;
  private payload: VaultPayload | null = null;
  private salt: Uint8Array | null = null;
  private unlockTimestamp: number = 0;
  private autoLockTimeout: number = DEFAULT_AUTO_LOCK_TIMEOUT;

  // ==========================================================================
  // Initialization
  // ==========================================================================

  /**
   * Checks if the vault has been initialized (password set).
   */
  async isInitialized(): Promise<boolean> {
    const result = await chrome.storage.local.get(STORAGE_KEY);
    return !!result[STORAGE_KEY];
  }

  /**
   * Initializes a new vault with the given password.
   *
   * @param password - User password for encryption
   * @throws Error if vault is already initialized
   */
  async initialize(password: string): Promise<void> {
    if (await this.isInitialized()) {
      throw new Error('Vault already initialized');
    }

    this.salt = generateSalt();
    this.derivedKey = await deriveKey(password, this.salt);

    this.payload = {
      keys: [],
      metadata: {
        createdAt: Date.now(),
        lastModified: Date.now(),
        keyCount: 0
      }
    };

    await this.persist();
    this.unlockTimestamp = Date.now();
  }

  /**
   * Initializes vault with a mnemonic phrase.
   * Stores the mnemonic encrypted in the vault and derives initial keys.
   *
   * @param password - User password for encryption
   * @param mnemonic - BIP-39 mnemonic (generated if not provided)
   * @returns The mnemonic phrase (for user backup)
   */
  async initializeWithMnemonic(
    password: string,
    mnemonic?: string
  ): Promise<string> {
    if (await this.isInitialized()) {
      throw new Error('Vault already initialized');
    }

    // Generate mnemonic if not provided
    const finalMnemonic = mnemonic || generateMnemonic(128);

    if (!validateMnemonic(finalMnemonic)) {
      throw new Error('Invalid mnemonic phrase');
    }

    this.salt = generateSalt();
    this.derivedKey = await deriveKey(password, this.salt);

    this.payload = {
      keys: [],
      metadata: {
        createdAt: Date.now(),
        lastModified: Date.now(),
        keyCount: 0
      },
      mnemonic: finalMnemonic
    };

    // Set unlock timestamp BEFORE deriving keys (isUnlocked() checks this)
    this.unlockTimestamp = Date.now();

    // Derive initial keys from mnemonic
    try {
      await this.deriveKeyFromMnemonic('ed25519', 'Accumulate Key 1');
      console.log('[KeyStore] ED25519 key derived successfully');
    } catch (err) {
      console.error('[KeyStore] Failed to derive ED25519 key:', err);
    }

    try {
      await this.deriveKeyFromMnemonic('secp256k1', 'Ethereum Key 1');
      console.log('[KeyStore] secp256k1 key derived successfully');
    } catch (err) {
      console.error('[KeyStore] Failed to derive secp256k1 key:', err);
    }

    await this.persist();

    return finalMnemonic;
  }

  // ==========================================================================
  // Lock / Unlock
  // ==========================================================================

  /**
   * Unlocks the vault with the given password.
   *
   * @param password - User password
   * @returns true if successful
   * @throws Error if password is incorrect or vault not initialized
   */
  async unlock(password: string): Promise<boolean> {
    const result = await chrome.storage.local.get(STORAGE_KEY);
    const vaultData: EncryptedVaultData = result[STORAGE_KEY];

    if (!vaultData) {
      throw new Error('Vault not initialized');
    }

    this.salt = fromBase64(vaultData.salt);
    this.derivedKey = await deriveKey(
      password,
      this.salt,
      vaultData.kdfParams.iterations
    );

    try {
      const iv = fromBase64(vaultData.iv);
      const ciphertext = fromBase64(vaultData.encryptedPayload);

      const decrypted = await decrypt(ciphertext, iv, this.derivedKey);
      this.payload = JSON.parse(decrypted);
      this.unlockTimestamp = Date.now();

      return true;
    } catch (e) {
      this.derivedKey = null;
      this.salt = null;
      throw new Error('Invalid password');
    }
  }

  /**
   * Locks the vault, clearing all sensitive data from memory.
   */
  lock(): void {
    this.derivedKey = null;
    this.payload = null;
    this.salt = null;
    this.unlockTimestamp = 0;
  }

  /**
   * Checks if the vault is currently unlocked.
   * Also handles auto-lock timeout.
   */
  isUnlocked(): boolean {
    if (!this.derivedKey || !this.payload) {
      return false;
    }

    // Check auto-lock timeout
    if (Date.now() - this.unlockTimestamp > this.autoLockTimeout) {
      this.lock();
      return false;
    }

    return true;
  }

  /**
   * Refreshes the unlock timestamp to prevent auto-lock.
   */
  refreshSession(): void {
    if (this.isUnlocked()) {
      this.unlockTimestamp = Date.now();
    }
  }

  /**
   * Sets the auto-lock timeout in milliseconds.
   */
  setAutoLockTimeout(timeout: number): void {
    this.autoLockTimeout = timeout;
  }

  // ==========================================================================
  // Key Management
  // ==========================================================================

  /**
   * Generates and adds a new key to the vault.
   *
   * @param type - Key type ('ed25519' or 'secp256k1')
   * @param name - User-friendly name for the key
   * @returns The created key (without private key)
   */
  async generateKey(type: KeyType, name: string): Promise<StoredKey> {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    let publicKey: Uint8Array;
    let privateKey: Uint8Array;
    let metadata: KeyMetadata = {};

    if (type === 'ed25519') {
      const keyPair = generateED25519Key();
      publicKey = keyPair.publicKey;
      privateKey = keyPair.privateKey;
      metadata.accumulateUrl = await generateLiteAccountUrl(publicKey);
    } else {
      const keyPair = generateSecp256k1Key(false);
      publicKey = keyPair.publicKey;
      privateKey = keyPair.privateKey;
      metadata.evmAddress = getEthAddress(publicKey);
    }

    const key: StoredKey = {
      id: generateUUID(),
      name,
      type,
      publicKey: toHex(publicKey),
      privateKey: toHex(privateKey),
      createdAt: Date.now(),
      metadata
    };

    this.payload!.keys.push(key);
    this.payload!.metadata.keyCount = this.payload!.keys.length;
    this.payload!.metadata.lastModified = Date.now();

    await this.persist();

    // Return key without private key
    return { ...key, privateKey: '[REDACTED]' };
  }

  /**
   * Derives a new key from the stored mnemonic.
   *
   * @param type - Key type ('ed25519' or 'secp256k1')
   * @param name - User-friendly name for the key
   * @returns The created key (without private key)
   */
  async deriveKeyFromMnemonic(type: KeyType, name: string): Promise<StoredKey> {
    console.log('[KeyStore] deriveKeyFromMnemonic called:', { type, name });

    if (!this.isUnlocked()) {
      console.error('[KeyStore] Vault is locked');
      throw new Error('Vault is locked');
    }

    if (!this.payload!.mnemonic) {
      console.error('[KeyStore] No mnemonic stored in vault');
      throw new Error('No mnemonic stored in vault. Please reset the vault and try again.');
    }

    console.log('[KeyStore] Mnemonic exists, proceeding with derivation');

    // Find next available index for this key type
    const existingPaths = this.payload!.keys
      .filter(k => k.type === type && k.derivationPath)
      .map(k => k.derivationPath!);

    const pathPrefix = type === 'ed25519'
      ? `m/44'/540'/0'/0'`
      : `m/44'/60'/0'/0`;

    let nextIndex = 0;
    for (const path of existingPaths) {
      const match = path.match(/\/(\d+)'?$/);
      if (match) {
        nextIndex = Math.max(nextIndex, parseInt(match[1], 10) + 1);
      }
    }

    let publicKey: Uint8Array;
    let privateKey: Uint8Array;
    let derivationPath: string;
    let metadata: KeyMetadata = { mnemonic: true };

    if (type === 'ed25519') {
      const derived = deriveED25519FromMnemonic(this.payload!.mnemonic, nextIndex);
      publicKey = derived.publicKey;
      privateKey = derived.privateKey;
      derivationPath = derived.path;
      metadata.accumulateUrl = await generateLiteAccountUrl(publicKey);
    } else {
      const derived = deriveSecp256k1FromMnemonic(this.payload!.mnemonic, nextIndex);
      publicKey = derived.publicKey;
      privateKey = derived.privateKey;
      derivationPath = derived.path;
      metadata.evmAddress = getEthAddress(publicKey);
    }

    const key: StoredKey = {
      id: generateUUID(),
      name,
      type,
      publicKey: toHex(publicKey),
      privateKey: toHex(privateKey),
      createdAt: Date.now(),
      derivationPath,
      metadata
    };

    this.payload!.keys.push(key);
    this.payload!.metadata.keyCount = this.payload!.keys.length;
    this.payload!.metadata.lastModified = Date.now();

    await this.persist();

    return { ...key, privateKey: '[REDACTED]' };
  }

  /**
   * Imports a key from a hex-encoded private key.
   *
   * @param type - Key type
   * @param privateKeyHex - Hex-encoded private key
   * @param name - User-friendly name
   * @returns The imported key (without private key)
   */
  async importKey(type: KeyType, privateKeyHex: string, name: string): Promise<StoredKey> {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    let publicKey: Uint8Array;
    let privateKey: Uint8Array;
    let metadata: KeyMetadata = {};

    if (type === 'ed25519') {
      const keyPair = ed25519FromPrivateKey(privateKeyHex);
      publicKey = keyPair.publicKey;
      privateKey = keyPair.privateKey;
      metadata.accumulateUrl = await generateLiteAccountUrl(publicKey);
    } else {
      const keyPair = secp256k1FromPrivateKeyHex(privateKeyHex, false);
      publicKey = keyPair.publicKey;
      privateKey = keyPair.privateKey;
      metadata.evmAddress = getEthAddress(publicKey);
    }

    const key: StoredKey = {
      id: generateUUID(),
      name,
      type,
      publicKey: toHex(publicKey),
      privateKey: toHex(privateKey),
      createdAt: Date.now(),
      metadata
    };

    this.payload!.keys.push(key);
    this.payload!.metadata.keyCount = this.payload!.keys.length;
    this.payload!.metadata.lastModified = Date.now();

    await this.persist();

    return { ...key, privateKey: '[REDACTED]' };
  }

  /**
   * Removes a key from the vault.
   *
   * @param keyId - ID of the key to remove
   */
  async removeKey(keyId: string): Promise<void> {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    const index = this.payload!.keys.findIndex(k => k.id === keyId);
    if (index === -1) {
      throw new Error('Key not found');
    }

    this.payload!.keys.splice(index, 1);
    this.payload!.metadata.keyCount = this.payload!.keys.length;
    this.payload!.metadata.lastModified = Date.now();

    await this.persist();
  }

  /**
   * Updates a key's name or metadata.
   *
   * @param keyId - ID of the key to update
   * @param updates - Fields to update
   */
  async updateKey(
    keyId: string,
    updates: { name?: string; metadata?: Partial<KeyMetadata> }
  ): Promise<void> {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    const key = this.payload!.keys.find(k => k.id === keyId);
    if (!key) {
      throw new Error('Key not found');
    }

    if (updates.name) {
      key.name = updates.name;
    }
    if (updates.metadata) {
      key.metadata = { ...key.metadata, ...updates.metadata };
    }

    this.payload!.metadata.lastModified = Date.now();
    await this.persist();
  }

  // ==========================================================================
  // Key Retrieval
  // ==========================================================================

  /**
   * Gets a key by ID (includes private key for signing).
   * Only available when vault is unlocked.
   */
  getKey(keyId: string): StoredKey | undefined {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    const key = this.payload!.keys.find(k => k.id === keyId);
    if (key) {
      key.lastUsedAt = Date.now();
    }
    return key;
  }

  /**
   * Gets all keys (without private keys) for display.
   */
  getAllKeys(): StoredKey[] {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    return this.payload!.keys.map(k => ({
      ...k,
      privateKey: '[REDACTED]'
    }));
  }

  /**
   * Finds a key by its Accumulate URL.
   */
  findKeyByAccumulateUrl(url: string): StoredKey | undefined {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    return this.payload!.keys.find(k => k.metadata.accumulateUrl === url);
  }

  /**
   * Finds a key by its Ethereum address.
   */
  findKeyByEvmAddress(address: string): StoredKey | undefined {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    const normalizedAddress = address.toLowerCase();
    return this.payload!.keys.find(
      k => k.metadata.evmAddress?.toLowerCase() === normalizedAddress
    );
  }

  /**
   * Gets keys filtered by type.
   */
  getKeysByType(type: KeyType): StoredKey[] {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }

    return this.payload!.keys
      .filter(k => k.type === type)
      .map(k => ({ ...k, privateKey: '[REDACTED]' }));
  }

  // ==========================================================================
  // Vault Info
  // ==========================================================================

  /**
   * Gets vault metadata.
   */
  getMetadata(): VaultMetadata | null {
    if (!this.isUnlocked()) {
      return null;
    }
    return { ...this.payload!.metadata };
  }

  /**
   * Checks if vault has a stored mnemonic.
   */
  hasMnemonic(): boolean {
    if (!this.isUnlocked()) {
      return false;
    }
    return !!this.payload!.mnemonic;
  }

  /**
   * Gets the stored mnemonic (for backup purposes).
   * Use with extreme caution - only show to user for backup.
   */
  getMnemonic(): string | null {
    if (!this.isUnlocked()) {
      throw new Error('Vault is locked');
    }
    return this.payload!.mnemonic || null;
  }

  // ==========================================================================
  // Password Management
  // ==========================================================================

  /**
   * Changes the vault password.
   *
   * @param currentPassword - Current password
   * @param newPassword - New password
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    // Verify current password by attempting unlock
    await this.unlock(currentPassword);

    // Generate new salt and derive new key
    this.salt = generateSalt();
    this.derivedKey = await deriveKey(newPassword, this.salt);

    // Re-encrypt with new key
    await this.persist();
    this.unlockTimestamp = Date.now();
  }

  // ==========================================================================
  // Persistence
  // ==========================================================================

  /**
   * Persists the vault to chrome.storage.local.
   */
  private async persist(): Promise<void> {
    if (!this.derivedKey || !this.payload || !this.salt) {
      throw new Error('Cannot persist: vault not properly initialized');
    }

    const payloadJson = JSON.stringify(this.payload);
    const { iv, ciphertext } = await encrypt(payloadJson, this.derivedKey);

    const vaultData: EncryptedVaultData = {
      version: 1,
      salt: toBase64(this.salt),
      iv: toBase64(iv),
      encryptedPayload: toBase64(ciphertext),
      kdfParams: {
        algorithm: 'pbkdf2',
        iterations: PBKDF2_ITERATIONS
      }
    };

    await chrome.storage.local.set({ [STORAGE_KEY]: vaultData });
  }

  /**
   * Exports the vault data (encrypted) for backup.
   */
  async exportVault(): Promise<string> {
    const result = await chrome.storage.local.get(STORAGE_KEY);
    if (!result[STORAGE_KEY]) {
      throw new Error('Vault not initialized');
    }
    return JSON.stringify(result[STORAGE_KEY]);
  }

  /**
   * Imports vault data from a backup.
   * Warning: This will overwrite the existing vault!
   */
  async importVault(vaultDataJson: string): Promise<void> {
    const vaultData: EncryptedVaultData = JSON.parse(vaultDataJson);

    // Validate structure
    if (!vaultData.version || !vaultData.salt || !vaultData.iv || !vaultData.encryptedPayload) {
      throw new Error('Invalid vault backup format');
    }

    await chrome.storage.local.set({ [STORAGE_KEY]: vaultData });
    this.lock();
  }

  /**
   * Completely resets the vault, deleting all data.
   */
  async reset(): Promise<void> {
    // Clear all storage
    await chrome.storage.local.clear();
    // Reset in-memory state
    this.salt = null;
    this.derivedKey = null;
    this.payload = null;
    this.unlockTimestamp = 0;
    console.log('[KeyStore] Vault completely reset');
  }
}

// =============================================================================
// Singleton Instance
// =============================================================================

export const keyStore = new KeyStore();
