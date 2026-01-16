# Bedrock Security Implementation

This repository contains the security-critical code from [Bedrock](https://bedrocklens.com), an AI-powered relationship communication analyzer.

## Why We're Sharing This

We believe users have the right to understand how their sensitive data is protected. By open-sourcing our security implementation, we demonstrate:

1. **End-to-End Encryption**: Your analysis results are encrypted with keys derived from your password. We cannot read them.
2. **Industry Standards**: AES-256-GCM encryption, PBKDF2 with 600,000 iterations (OWASP 2024 recommendation)
3. **No Trust Required**: You can verify our claims yourself

## Security Architecture

### Client-Side Encryption

When you log in with email/password, your data is encrypted **before** it leaves your browser:

```
Password + Salt → PBKDF2 (600,000 iterations) → AES-256-GCM Key
                                                       ↓
Your Data → Encrypt → Ciphertext → Server Storage
```

**Key Points:**
- Your password is never sent to our servers (only for initial authentication)
- The encryption key is derived locally in your browser
- We store only encrypted ciphertext - we cannot decrypt your data
- If you reset your password, old encrypted data becomes permanently inaccessible

### Server-Side Encryption (Defense in Depth)

For background processing, we add a second layer of encryption:

- Data at rest is encrypted with a server-managed key
- This protects against database breaches
- The key is stored separately from the database

### Rate Limiting

All API endpoints are rate-limited to prevent abuse:

- Configurable per-endpoint limits
- Standard `X-RateLimit-*` headers
- Automatic cleanup of expired entries

### Input Validation

Comprehensive validation prevents resource exhaustion:

- Payload size limits
- Array length limits
- Text length limits
- UUID and email format validation

## Files

| File | Purpose |
|------|---------|
| [`client/encryption.ts`](client/encryption.ts) | Browser-side AES-256-GCM encryption with PBKDF2 key derivation |
| [`server/encryption.ts`](server/encryption.ts) | Server-side payload encryption for background jobs |
| [`server/rateLimit.ts`](server/rateLimit.ts) | Per-user rate limiting with configurable windows |
| [`server/validation.ts`](server/validation.ts) | Input validation and sanitization utilities |

## Usage

### Client-Side Encryption

```typescript
import {
  deriveKey,
  cacheKey,
  persistKey,
  encryptData,
  decryptData,
  restoreKeyFromStorage,
  clearCachedKey,
  clearPersistedKey,
  generateSalt,
} from './client/encryption';

// On login: derive and cache the encryption key
const salt = await getUserSaltFromServer(); // Or generateSalt() for new users
const key = await deriveKey(password, salt);
cacheKey(key, salt);
await persistKey(key, salt); // Survives page refresh

// Encrypt sensitive data before sending to server
const encrypted = await encryptData({ sensitiveField: 'value' });
await sendToServer(encrypted);

// Decrypt data received from server
const decrypted = await decryptData(encrypted);

// On logout: clear all keys
clearCachedKey();
await clearPersistedKey();

// On app startup: restore key if session exists
const restored = await restoreKeyFromStorage();
```

### Server-Side Encryption

```typescript
import {
  encryptPayload,
  decryptPayload,
  isEncryptionConfigured,
} from './server/encryption';

// Check if encryption is configured
if (!isEncryptionConfigured()) {
  throw new Error('PAYLOAD_ENCRYPTION_KEY not set');
}

// Encrypt before storing in database
const encrypted = await encryptPayload({ userId: '123', data: 'sensitive' });
await db.insert({ payload: JSON.stringify(encrypted) });

// Decrypt when processing
const row = await db.get(id);
const decrypted = await decryptPayload(JSON.parse(row.payload));
```

### Rate Limiting

```typescript
import {
  checkRateLimit,
  createRateLimitResponse,
} from './server/rateLimit';

// In your request handler
const userId = getUserId(request);
const result = checkRateLimit(userId, {
  windowMs: 60000,    // 1 minute
  maxRequests: 10,    // 10 requests per minute
});

if (!result.allowed) {
  return createRateLimitResponse(result);
}

// Process request and include rate limit headers
return new Response(data, {
  headers: result.headers,
});
```

### Input Validation

```typescript
import {
  validatePayloadSize,
  isValidUUID,
  isValidEmail,
  createValidationErrorResponse,
} from './server/validation';

// Validate request payload
const validation = validatePayloadSize(
  request.items,
  (item) => item.content, // Extract text for size calculation
  { maxItems: 50, maxTextLength: 20000 }
);

if (!validation.valid) {
  return createValidationErrorResponse(validation.error);
}

// Validate individual fields
if (!isValidUUID(request.id)) {
  return createValidationErrorResponse('Invalid ID format');
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYLOAD_ENCRYPTION_KEY` | For server encryption | 32-byte base64-encoded key |

Generate a key:
```bash
openssl rand -base64 32
```

## Security Contact

Found a vulnerability? Please report it responsibly:

- Email: security@bedrocklens.com
- See [SECURITY.md](SECURITY.md) for our disclosure policy

## License

MIT License - See [LICENSE](LICENSE) for details.

---

Built with transparency by [Bedrock](https://bedrocklens.com)
