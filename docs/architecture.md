# Security Architecture

This document describes the defense-in-depth security architecture used by Bedrock.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT BROWSER                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Password + Salt → PBKDF2 → AES-256-GCM Key            │   │
│  │                              ↓                          │   │
│  │  User Data → Encrypt → Ciphertext                      │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                         HTTPS Only
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                       EDGE FUNCTIONS                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Layer 1: JWT Validation                                │   │
│  │  Layer 2: Ownership Verification                        │   │
│  │  Layer 3: Rate Limiting                                 │   │
│  │  Layer 4: Input Validation                              │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                         DATABASE                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Row-Level Security (RLS) Policies                      │   │
│  │  Encrypted at Rest                                      │   │
│  │  Client-encrypted fields are double-encrypted           │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Layer 1: Client-Side Encryption

### Key Derivation

```typescript
PBKDF2(password, salt, iterations=600000, hash=SHA-256) → 256-bit key
```

**Why 600,000 iterations?**
- OWASP 2024 recommendation for PBKDF2-HMAC-SHA256
- Balances security with user experience (~500ms derivation time)
- Makes brute-force attacks computationally expensive

### Encryption

```typescript
AES-GCM(key, iv=random_96_bits, plaintext) → ciphertext + auth_tag
```

**Why AES-256-GCM?**
- Authenticated encryption (integrity + confidentiality)
- Hardware-accelerated on modern CPUs
- Widely audited and trusted

### Key Storage

```
IndexedDB (browser)
├── Survives page refresh
├── Cleared on logout
└── Not accessible to JavaScript from other origins
```

## Layer 2: Server-Side Authentication

### JWT Validation

All user-facing endpoints validate JWT tokens:

```typescript
// Extract token from Authorization header
const token = request.headers.get('Authorization')?.replace('Bearer ', '');

// Validate with auth provider
const { data: { user }, error } = await supabase.auth.getUser(token);

if (error || !user) {
  return new Response('Unauthorized', { status: 401 });
}
```

### Ownership Verification

Resources are always checked for ownership:

```typescript
// Fetch the resource
const resource = await db.get(resourceId);

// Verify ownership (don't reveal existence to non-owners)
if (resource.user_id !== user.id) {
  return new Response('Not found', { status: 404 });
}
```

## Layer 3: Rate Limiting

### Implementation

```typescript
Per-user sliding window rate limiter
├── Window: Configurable (default 60 seconds)
├── Limit: Configurable per endpoint
└── Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
```

### Response on Limit

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704067260
Retry-After: 45

{
  "error": "Too many requests",
  "retryAfter": 45
}
```

## Layer 4: Input Validation

### Size Limits

| Parameter | Limit | Purpose |
|-----------|-------|---------|
| Items per batch | Configurable | Prevent memory exhaustion |
| Sub-items per item | Configurable | Prevent deep nesting attacks |
| Text field length | Configurable | Prevent oversized strings |
| Total payload | Configurable | Prevent large request bodies |

### Format Validation

```typescript
// UUID validation (v4)
/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

// Email validation (basic)
/^[^\s@]+@[^\s@]+\.[^\s@]+$/

// Base64 validation
/^[A-Za-z0-9+/=]+$/
```

## Layer 5: Database Security

### Row-Level Security (RLS)

Even if application code has bugs, database policies enforce access control:

```sql
-- Users can only read their own data
CREATE POLICY "Users can view own data"
  ON user_data FOR SELECT
  USING (auth.uid() = user_id);

-- Users can only update their own data
CREATE POLICY "Users can update own data"
  ON user_data FOR UPDATE
  USING (auth.uid() = user_id);
```

### Encryption at Rest

- Database-level encryption for all data
- Client-encrypted fields are double-encrypted
- Backup encryption

## Security Properties

### What We Can See

- Encrypted ciphertext (we cannot decrypt)
- Metadata: timestamps, user IDs, sizes
- Aggregate statistics

### What We Cannot See

- Your decrypted data
- Your password (only hash stored by auth provider)
- Your encryption key (never leaves your browser)

### What Happens If...

| Scenario | Impact |
|----------|--------|
| Database breach | Attackers get encrypted ciphertext only |
| Server compromise | Cannot decrypt client-encrypted data |
| Password reset | Old encrypted data permanently lost |
| Lost browser data | Re-derive key on next login |

## Threat Model

### Protected Against

- Passive network eavesdropping (HTTPS)
- Database breaches (client-side encryption)
- Server-side data access (end-to-end encryption)
- Brute-force attacks (rate limiting, PBKDF2)
- Injection attacks (input validation)
- Unauthorized access (JWT + RLS)

### Not Protected Against

- Compromised client device
- Phishing attacks
- Weak user passwords
- Browser vulnerabilities
- Sophisticated nation-state attacks

## Recommendations

1. **Use strong passwords** - The encryption is only as strong as your password
2. **Don't share devices** - Keys are stored in browser storage
3. **Log out on shared computers** - Clears encryption keys
4. **Keep browser updated** - Web Crypto API security depends on it
