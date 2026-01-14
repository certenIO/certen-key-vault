/**
 * Certen Key Vault - Vault Module Exports
 */

// Crypto utilities
export {
  deriveKey,
  encrypt,
  decrypt,
  generateSalt,
  randomBytes,
  generateUUID,
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  secureWipe,
  PBKDF2_ITERATIONS,
  SALT_LENGTH,
  IV_LENGTH,
  KEY_LENGTH
} from './crypto';

// ED25519 operations
export {
  generateED25519Key,
  ed25519FromSeed,
  ed25519FromPrivateKey,
  signED25519,
  signED25519Hex,
  verifyED25519,
  generateLiteAccountUrl,
  getPublicKeyHash,
  type ED25519KeyPair
} from './ed25519';

// secp256k1 operations
export {
  generateSecp256k1Key,
  secp256k1FromPrivateKey,
  secp256k1FromPrivateKeyHex,
  signSecp256k1,
  signSecp256k1Hex,
  verifySecp256k1,
  getEthAddress,
  hashEthSignedMessage,
  signEthPersonalMessage,
  type Secp256k1KeyPair,
  type EthereumSignature
} from './secp256k1';

// Mnemonic and HD derivation
export {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  deriveED25519FromMnemonic,
  deriveSecp256k1FromMnemonic,
  deriveAllKeysFromMnemonic,
  getNextDerivationIndex,
  ACCUMULATE_COIN_TYPE,
  ETHEREUM_COIN_TYPE,
  DEFAULT_ACCUMULATE_PATH,
  DEFAULT_ETHEREUM_PATH,
  type DerivedED25519Key,
  type DerivedSecp256k1Key
} from './mnemonic';

// Key Store
export { KeyStore, keyStore } from './keyStore';
