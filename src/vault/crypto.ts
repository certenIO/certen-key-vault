/**
 * Certen Key Vault - Cryptographic Utilities
 *
 * Uses Web Crypto API for secure key derivation and encryption.
 * - PBKDF2 with SHA-512 for key derivation (600K iterations - OWASP 2023)
 * - AES-256-GCM for authenticated encryption
 */

// =============================================================================
// Constants
// =============================================================================

export const PBKDF2_ITERATIONS = 600000;  // OWASP 2023 minimum recommendation
export const SALT_LENGTH = 32;            // 256 bits
export const IV_LENGTH = 12;              // 96 bits (GCM standard)
export const KEY_LENGTH = 32;             // 256 bits for AES-256

// =============================================================================
// Key Derivation
// =============================================================================

/**
 * Derives an AES-256 encryption key from a password using PBKDF2.
 *
 * @param password - User password
 * @param salt - Random salt (32 bytes)
 * @param iterations - PBKDF2 iterations (default: 600000)
 * @returns CryptoKey for AES-GCM encryption/decryption
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  // Import password as raw key material
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // Derive AES-256 key using PBKDF2-SHA512
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: iterations,
      hash: 'SHA-512'
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,  // Not extractable
    ['encrypt', 'decrypt']
  );
}

// =============================================================================
// Encryption / Decryption
// =============================================================================

/**
 * Encrypts data using AES-256-GCM.
 *
 * @param data - Plaintext string to encrypt
 * @param key - AES-256 CryptoKey
 * @returns Object containing IV and ciphertext
 */
export async function encrypt(
  data: string,
  key: CryptoKey
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoder = new TextEncoder();

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(data)
  );

  return {
    iv,
    ciphertext: new Uint8Array(ciphertext)
  };
}

/**
 * Decrypts data using AES-256-GCM.
 *
 * @param ciphertext - Encrypted data
 * @param iv - Initialization vector used for encryption
 * @param key - AES-256 CryptoKey
 * @returns Decrypted plaintext string
 * @throws Error if decryption fails (wrong password or tampered data)
 */
export async function decrypt(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  key: CryptoKey
): Promise<string> {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    ciphertext.buffer as ArrayBuffer
  );

  const decoder = new TextDecoder();
  return decoder.decode(plaintext);
}

// =============================================================================
// Random Generation
// =============================================================================

/**
 * Generates a cryptographically secure random salt.
 *
 * @param length - Length in bytes (default: 32)
 * @returns Random salt as Uint8Array
 */
export function generateSalt(length: number = SALT_LENGTH): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generates a cryptographically secure random bytes.
 *
 * @param length - Number of bytes
 * @returns Random bytes as Uint8Array
 */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generates a UUID v4.
 *
 * @returns UUID string
 */
export function generateUUID(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));

  // Set version (4) and variant (RFC 4122)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// =============================================================================
// Encoding Utilities
// =============================================================================

/**
 * Converts Uint8Array to hex string.
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts hex string to Uint8Array.
 */
export function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Converts Uint8Array to base64 string.
 */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts base64 string to Uint8Array.
 */
export function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// =============================================================================
// Secure Memory Utilities
// =============================================================================

/**
 * Securely clears sensitive data from memory.
 * Note: JavaScript garbage collection may still leave traces.
 */
export function secureWipe(buffer: Uint8Array): void {
  crypto.getRandomValues(buffer);
  buffer.fill(0);
}
