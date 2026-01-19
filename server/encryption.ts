/**
 * Server-Side Encryption for Sensitive Payload Data
 * Uses AES-256-GCM for authenticated encryption
 *
 * This module provides encryption for data that must be stored temporarily
 * on the server (e.g., background job payloads). The key should be stored
 * as an environment variable, not in code.
 *
 * Key Generation:
 *   openssl rand -base64 32
 *   - or -
 *   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
 *
 * IMPORTANT: If the encryption key is lost, encrypted data cannot be recovered.
 * Store the key securely and consider a backup strategy.
 *
 * @license MIT
 * @see https://github.com/gemkuru/bedrock-security
 */

// ============================================================================
// Types
// ============================================================================

interface EncryptedPayload {
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded encrypted data */
  data: string;
  /** Version for future algorithm changes */
  v: 1;
}

// ============================================================================
// Configuration
// ============================================================================

/**
 * Get the encryption key from environment.
 * Override this function for your runtime (Deno, Node.js, Cloudflare Workers, etc.)
 */
export function getEncryptionKeyFromEnv(): string | undefined {
  // Deno
  if (typeof Deno !== 'undefined') {
    return Deno.env.get('PAYLOAD_ENCRYPTION_KEY');
  }
  // Node.js
  if (typeof process !== 'undefined' && process.env) {
    return process.env.PAYLOAD_ENCRYPTION_KEY;
  }
  return undefined;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert Uint8Array to base64 string without stack overflow
 * Uses chunked processing for large arrays instead of spread operator
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 8192;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode.apply(null, chunk as unknown as number[]);
  }
  return btoa(result);
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ============================================================================
// Key Management
// ============================================================================

let cachedKey: CryptoKey | null = null;

/**
 * Get or derive the encryption key from environment variable
 * Key is cached for performance
 */
async function getEncryptionKey(): Promise<CryptoKey> {
  if (cachedKey) {
    return cachedKey;
  }

  const keyBase64 = getEncryptionKeyFromEnv();
  if (!keyBase64) {
    throw new Error('Encryption key environment variable not configured');
  }

  // Decode the base64 key
  const keyBytes = Uint8Array.from(atob(keyBase64), (c) => c.charCodeAt(0));

  // Validate key length (256 bits = 32 bytes)
  if (keyBytes.length !== 32) {
    throw new Error(
      `Invalid encryption key length: expected 32 bytes, got ${keyBytes.length}`
    );
  }

  // Import as AES-GCM key
  cachedKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM', length: 256 },
    false, // not extractable
    ['encrypt', 'decrypt']
  );

  return cachedKey;
}

/**
 * Clear the cached key (useful for testing or key rotation)
 */
export function clearCachedKey(): void {
  cachedKey = null;
}

// ============================================================================
// Encryption Functions
// ============================================================================

/**
 * Encrypt a payload object using AES-256-GCM
 * Returns an encrypted payload object that can be stored in the database
 */
export async function encryptPayload<T>(payload: T): Promise<EncryptedPayload> {
  const key = await getEncryptionKey();

  // Generate random 96-bit IV (recommended for GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Serialize payload to JSON
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));

  // Encrypt with AES-GCM
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  // Return as base64-encoded object
  return {
    iv: uint8ArrayToBase64(iv),
    data: uint8ArrayToBase64(new Uint8Array(ciphertext)),
    v: 1,
  };
}

/**
 * Decrypt an encrypted payload back to its original object
 */
export async function decryptPayload<T>(
  encrypted: EncryptedPayload
): Promise<T> {
  // Validate version
  if (encrypted.v !== 1) {
    throw new Error(`Unsupported encryption version: ${encrypted.v}`);
  }

  const key = await getEncryptionKey();

  // Decode base64
  const iv = base64ToUint8Array(encrypted.iv);
  const ciphertext = base64ToUint8Array(encrypted.data);

  // Decrypt with AES-GCM
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  // Parse JSON back to object
  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as T;
}

/**
 * Check if encryption is configured
 * Returns false if the encryption key environment variable is not set
 */
export function isEncryptionConfigured(): boolean {
  return !!getEncryptionKeyFromEnv();
}

/**
 * Type guard to check if data is an encrypted payload
 */
export function isEncryptedPayload(data: unknown): data is EncryptedPayload {
  if (typeof data !== 'object' || data === null) {
    return false;
  }
  const obj = data as Record<string, unknown>;
  return (
    typeof obj.iv === 'string' &&
    typeof obj.data === 'string' &&
    obj.v === 1
  );
}
