/**
 * Client-Side Encryption for Sensitive Data
 *
 * Implements end-to-end encryption using Web Crypto API.
 * The encryption key is derived from the user's password using PBKDF2,
 * ensuring that only the user can decrypt their data.
 *
 * Security notes:
 * - Key derivation uses PBKDF2 with 600,000 iterations per OWASP recommendation
 *   (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
 * - Encryption uses AES-256-GCM for authenticated encryption
 * - Salt is unique per user (stored in profile, not secret)
 * - Key is persisted in IndexedDB (survives page refresh, cleared on logout)
 * - Password/passphrase is used only for derivation, never stored
 *
 * IMPORTANT: If a user resets their password, their encryption key changes
 * and all previously encrypted data becomes permanently inaccessible.
 *
 * @license MIT
 * @see https://github.com/gemkuru/bedrock-security
 */

// Configuration constants
// OWASP 2024 recommendation: 600,000 iterations for PBKDF2-HMAC-SHA256
const PBKDF2_ITERATIONS = 600000;
const SALT_LENGTH = 16; // bytes
const KEY_LENGTH = 256; // bits
const IV_LENGTH = 12; // bytes for AES-GCM (96 bits recommended)

// IndexedDB configuration - customize these for your application
const DB_NAME = 'app-encryption';
const DB_VERSION = 1;
const KEY_STORE = 'encryption-keys';
const KEY_ID = 'user-encryption-key';

/**
 * Stored key data structure for IndexedDB
 * CryptoKey objects can be stored directly in IndexedDB (structured-cloneable)
 */
interface StoredKeyData {
  id: string;
  key: CryptoKey;
  salt: string;
  createdAt: number;
}

/**
 * Encrypted data structure for storage
 */
export interface EncryptedData {
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded ciphertext */
  data: string;
  /** Version for future algorithm changes */
  v: 2;
}

// In-memory key cache (also persisted to IndexedDB for page refresh survival)
let cachedKey: CryptoKey | null = null;
let cachedSalt: string | null = null;

// ============================================================================
// IndexedDB Persistence Layer
// ============================================================================

/**
 * Check if IndexedDB is available
 * May not be available in private browsing mode on some browsers
 */
export function isIndexedDBAvailable(): boolean {
  try {
    return typeof indexedDB !== 'undefined' && indexedDB !== null;
  } catch {
    return false;
  }
}

/**
 * Open the IndexedDB database for key storage
 * Creates the database and object store if they don't exist
 */
function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!isIndexedDBAvailable()) {
      reject(new Error('IndexedDB is not available'));
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      console.error('[ENCRYPTION_DB_OPEN_ERROR]', request.error);
      reject(new Error('Failed to open encryption key database'));
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Create object store for encryption keys if it doesn't exist
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE, { keyPath: 'id' });
      }
    };
  });
}

/**
 * Persist encryption key to IndexedDB
 * Called after successful key derivation from password or passphrase
 *
 * @param key - The CryptoKey to persist
 * @param salt - The salt used for key derivation
 */
export async function persistKey(key: CryptoKey, salt: string): Promise<void> {
  if (!isIndexedDBAvailable()) {
    console.warn('[ENCRYPTION_INDEXEDDB_NOT_AVAILABLE] Key will not persist across page refresh');
    return;
  }

  try {
    const db = await openKeyDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(KEY_STORE, 'readwrite');
      const store = transaction.objectStore(KEY_STORE);

      const keyData: StoredKeyData = {
        id: KEY_ID,
        key,
        salt,
        createdAt: Date.now(),
      };

      const request = store.put(keyData);

      request.onerror = () => {
        console.error('[ENCRYPTION_STORE_ERROR]', request.error);
        reject(new Error('Failed to persist encryption key'));
      };

      request.onsuccess = () => {
        resolve();
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (err) {
    console.error('[ENCRYPTION_PERSIST_KEY_FAILED]', err);
    // Don't throw - key persistence is optional enhancement
  }
}

/**
 * Retrieve persisted key from IndexedDB
 * Returns null if no key is stored or IndexedDB is not available
 */
export async function getPersistedKey(): Promise<{ key: CryptoKey; salt: string } | null> {
  if (!isIndexedDBAvailable()) {
    return null;
  }

  try {
    const db = await openKeyDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(KEY_STORE, 'readonly');
      const store = transaction.objectStore(KEY_STORE);
      const request = store.get(KEY_ID);

      request.onerror = () => {
        console.error('[ENCRYPTION_RETRIEVE_ERROR]', request.error);
        reject(new Error('Failed to retrieve encryption key'));
      };

      request.onsuccess = () => {
        const data = request.result as StoredKeyData | undefined;
        if (data && data.key && data.salt) {
          resolve({ key: data.key, salt: data.salt });
        } else {
          resolve(null);
        }
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (err) {
    console.error('[ENCRYPTION_GET_PERSISTED_KEY_FAILED]', err);
    return null;
  }
}

/**
 * Clear persisted key from IndexedDB
 * Called on logout
 */
export async function clearPersistedKey(): Promise<void> {
  if (!isIndexedDBAvailable()) {
    return;
  }

  try {
    const db = await openKeyDatabase();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction(KEY_STORE, 'readwrite');
      const store = transaction.objectStore(KEY_STORE);
      const request = store.delete(KEY_ID);

      request.onerror = () => {
        console.error('[ENCRYPTION_DELETE_ERROR]', request.error);
        reject(new Error('Failed to clear encryption key'));
      };

      request.onsuccess = () => {
        resolve();
      };

      transaction.oncomplete = () => {
        db.close();
      };
    });
  } catch (err) {
    console.error('[ENCRYPTION_CLEAR_PERSISTED_KEY_FAILED]', err);
    // Don't throw - clearing is best effort
  }
}

/**
 * Restore key from IndexedDB to memory cache
 * Call on app initialization when session exists
 *
 * @returns true if key was restored, false otherwise
 */
export async function restoreKeyFromStorage(): Promise<boolean> {
  try {
    const stored = await getPersistedKey();
    if (stored) {
      cachedKey = stored.key;
      cachedSalt = stored.salt;
      return true;
    }
    return false;
  } catch (err) {
    console.error('[ENCRYPTION_RESTORE_KEY_FAILED]', err);
    return false;
  }
}

/**
 * Generate a new random salt for a user
 * Called once during first password-based login
 */
export function generateSalt(): string {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  return btoa(String.fromCharCode(...salt));
}

/**
 * Derive encryption key from password using PBKDF2
 *
 * @param password - User's password (used only for derivation)
 * @param saltBase64 - Base64-encoded salt from user's profile
 * @returns CryptoKey for AES-GCM encryption/decryption
 * @throws Error with user-friendly message on failure
 */
export async function deriveKey(
  password: string,
  saltBase64: string
): Promise<CryptoKey> {
  // Validate inputs
  if (!password) {
    throw new Error('Password is required for encryption key derivation.');
  }
  if (!saltBase64) {
    throw new Error('Encryption salt is missing. Please contact support.');
  }

  // Decode salt from base64
  let salt: Uint8Array;
  try {
    salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
  } catch (err) {
    console.error('[ENCRYPTION_DERIVE_KEY_INVALID_SALT]', { error: err });
    throw new Error('Invalid encryption salt format. Your encryption settings may be corrupted.');
  }

  try {
    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    // Derive AES-GCM key using PBKDF2
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: KEY_LENGTH },
      false, // not extractable
      ['encrypt', 'decrypt']
    );

    return key;
  } catch (err) {
    console.error('[ENCRYPTION_DERIVE_KEY_CRYPTO_ERROR]', { error: err });
    if (err instanceof DOMException && err.name === 'NotSupportedError') {
      throw new Error('Your browser does not support the required encryption features. Please use a modern browser (Chrome, Firefox, Safari, or Edge).');
    }
    throw new Error('Failed to derive encryption key. Please try again or use a different browser.');
  }
}

/**
 * Cache the derived key in memory
 * Call after successful password-based login
 *
 * @param key - Derived CryptoKey
 * @param saltBase64 - Salt used for derivation (for reference)
 */
export function cacheKey(key: CryptoKey, saltBase64: string): void {
  cachedKey = key;
  cachedSalt = saltBase64;
}

/**
 * Clear cached key from memory
 * Call on logout
 */
export function clearCachedKey(): void {
  cachedKey = null;
  cachedSalt = null;
}

/**
 * Get cached key or throw if not available
 * @throws Error if key not cached (user not authenticated with password)
 */
export function getCachedKey(): CryptoKey {
  if (!cachedKey) {
    throw new Error('Encryption key not available. Please re-authenticate with your password.');
  }
  return cachedKey;
}

/**
 * Check if encryption key is cached (available for use)
 */
export function isKeyAvailable(): boolean {
  return cachedKey !== null;
}

/**
 * Get the cached salt (for debugging/verification)
 */
export function getCachedSalt(): string | null {
  return cachedSalt;
}

/**
 * Encrypt data using cached key
 *
 * @param data - Any JSON-serializable data to encrypt
 * @returns Encrypted data structure for storage
 * @throws Error if key not available
 */
export async function encryptData<T>(data: T): Promise<EncryptedData> {
  const key = getCachedKey();

  // Generate random IV for this encryption
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // Serialize data to JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(data));

  // Encrypt with AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  // Return as base64-encoded structure
  return {
    iv: btoa(String.fromCharCode(...iv)),
    data: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    v: 2,
  };
}

/**
 * Decrypt data using cached key
 *
 * @param encrypted - Encrypted data structure
 * @returns Decrypted and parsed data
 * @throws Error with user-friendly message if decryption fails
 */
export async function decryptData<T>(encrypted: EncryptedData): Promise<T> {
  // Validate version
  if (encrypted.v !== 2) {
    throw new Error(`Unsupported encryption version: ${encrypted.v}. This data may be from an older version of the application.`);
  }

  const key = getCachedKey();

  // Decode base64
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    iv = Uint8Array.from(atob(encrypted.iv), c => c.charCodeAt(0));
    ciphertext = Uint8Array.from(atob(encrypted.data), c => c.charCodeAt(0));
  } catch (err) {
    console.error('[ENCRYPTION_DECRYPT_DATA_INVALID_FORMAT]', { error: err });
    throw new Error('The encrypted data is corrupted and cannot be decrypted.');
  }

  // Decrypt with AES-GCM
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
  } catch (err) {
    console.error('[ENCRYPTION_DECRYPT_DATA_CRYPTO_ERROR]', { error: err });
    // OperationError typically means wrong key (authentication tag mismatch)
    if (err instanceof DOMException && err.name === 'OperationError') {
      throw new Error(
        'Decryption failed. This usually means your password has changed since this data was encrypted. ' +
        'Unfortunately, data encrypted with your old password cannot be recovered.'
      );
    }
    throw new Error('Failed to decrypt data. The data may be corrupted or incompatible.');
  }

  // Parse JSON back to object
  try {
    const json = new TextDecoder().decode(plaintext);
    return JSON.parse(json) as T;
  } catch (err) {
    console.error('[ENCRYPTION_DECRYPT_DATA_PARSE_ERROR]', { error: err });
    throw new Error('Decrypted data is not valid JSON. The data may be corrupted.');
  }
}

/**
 * Check if data is in encrypted format
 * Used to determine whether decryption is needed.
 * Validates structure, types, and basic base64 format.
 */
export function isEncryptedData(data: unknown): data is EncryptedData {
  if (typeof data !== 'object' || data === null) {
    return false;
  }

  const obj = data as Record<string, unknown>;

  // Check field types and non-empty
  if (typeof obj.iv !== 'string' || obj.iv.length === 0) {
    return false;
  }
  if (typeof obj.data !== 'string' || obj.data.length === 0) {
    return false;
  }
  if (obj.v !== 2) {
    return false;
  }

  // Basic base64 format validation
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(obj.iv) && base64Regex.test(obj.data);
}

/**
 * Type guard for checking encryption status from database
 */
export type EncryptionStatus = 'legacy' | 'plaintext' | 'encrypted';

export function isEncryptionStatus(value: unknown): value is EncryptionStatus {
  return value === 'legacy' || value === 'plaintext' || value === 'encrypted';
}
