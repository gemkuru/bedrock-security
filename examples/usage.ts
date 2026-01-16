/**
 * Example Usage of Bedrock Security Modules
 *
 * This file demonstrates how to integrate the security modules
 * into your own application.
 */

// ============================================================================
// Client-Side Encryption Example
// ============================================================================

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
  isKeyAvailable,
  isEncryptedData,
  type EncryptedData,
} from '../client/encryption';

/**
 * Example: Handle user login with encryption setup
 */
async function handleLogin(email: string, password: string): Promise<void> {
  // 1. Authenticate with your auth provider (e.g., Supabase, Auth0)
  const { user, session } = await yourAuthProvider.signIn(email, password);

  // 2. Get or create encryption salt for this user
  let salt = await fetchUserSalt(user.id);
  if (!salt) {
    salt = generateSalt();
    await saveUserSalt(user.id, salt);
  }

  // 3. Derive encryption key from password
  const key = await deriveKey(password, salt);

  // 4. Cache key in memory and persist to IndexedDB
  cacheKey(key, salt);
  await persistKey(key, salt);

  console.log('Login complete, encryption ready');
}

/**
 * Example: Handle app startup (restore session)
 */
async function handleAppStartup(): Promise<void> {
  // Check if user has an existing session
  const session = await yourAuthProvider.getSession();
  if (!session) {
    return; // No session, user needs to log in
  }

  // Try to restore encryption key from IndexedDB
  const restored = await restoreKeyFromStorage();
  if (restored) {
    console.log('Encryption key restored from storage');
  } else {
    console.log('No encryption key found - user may need to re-authenticate');
    // Optionally prompt for password to re-derive key
  }
}

/**
 * Example: Handle user logout
 */
async function handleLogout(): Promise<void> {
  // 1. Sign out from auth provider
  await yourAuthProvider.signOut();

  // 2. Clear encryption keys from memory and storage
  clearCachedKey();
  await clearPersistedKey();

  console.log('Logged out, encryption keys cleared');
}

/**
 * Example: Save encrypted data to server
 */
async function saveSecureData(data: Record<string, unknown>): Promise<void> {
  if (!isKeyAvailable()) {
    throw new Error('Encryption key not available. Please log in again.');
  }

  // Encrypt data client-side
  const encrypted = await encryptData(data);

  // Send encrypted data to server
  await fetch('/api/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ encrypted }),
  });
}

/**
 * Example: Load and decrypt data from server
 */
async function loadSecureData(id: string): Promise<Record<string, unknown>> {
  // Fetch encrypted data from server
  const response = await fetch(`/api/load/${id}`);
  const { encrypted } = await response.json();

  // Check if data is encrypted
  if (isEncryptedData(encrypted)) {
    return await decryptData(encrypted);
  }

  // Handle legacy unencrypted data
  return encrypted;
}

// ============================================================================
// Server-Side Encryption Example
// ============================================================================

import {
  encryptPayload,
  decryptPayload,
  isEncryptionConfigured,
  isEncryptedPayload,
} from '../server/encryption';

/**
 * Example: Queue a background job with encrypted payload
 */
async function queueBackgroundJob(
  userId: string,
  sensitiveData: Record<string, unknown>
): Promise<void> {
  // Verify encryption is configured
  if (!isEncryptionConfigured()) {
    throw new Error('Server encryption not configured');
  }

  // Encrypt the payload before storing
  const encrypted = await encryptPayload({
    userId,
    data: sensitiveData,
    createdAt: new Date().toISOString(),
  });

  // Store in database
  await db.insert('background_jobs', {
    status: 'pending',
    payload: JSON.stringify(encrypted),
  });
}

/**
 * Example: Process a background job
 */
async function processBackgroundJob(jobId: string): Promise<void> {
  // Fetch job from database
  const job = await db.get('background_jobs', jobId);
  const payload = JSON.parse(job.payload);

  // Decrypt if encrypted
  let data: { userId: string; data: Record<string, unknown> };
  if (isEncryptedPayload(payload)) {
    data = await decryptPayload(payload);
  } else {
    // Handle legacy unencrypted payloads
    console.warn('Processing unencrypted payload - consider migrating');
    data = payload;
  }

  // Process the job...
  console.log(`Processing job for user ${data.userId}`);
}

// ============================================================================
// Rate Limiting Example
// ============================================================================

import {
  checkRateLimit,
  getRateLimitHeaders,
  createRateLimitResponse,
  type RateLimitConfig,
} from '../server/rateLimit';

/**
 * Example: Rate-limited API endpoint handler
 */
async function handleApiRequest(request: Request): Promise<Response> {
  // Extract user identifier (e.g., from JWT, API key, or IP)
  const userId = await getUserIdFromRequest(request);

  // Check rate limit
  const rateLimitConfig: RateLimitConfig = {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 10, // 10 requests per minute
  };

  const rateLimit = checkRateLimit(userId, rateLimitConfig);

  if (!rateLimit.allowed) {
    return createRateLimitResponse(rateLimit);
  }

  // Process the request...
  const result = await processRequest(request);

  // Include rate limit headers in response
  return new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      ...rateLimit.headers,
    },
  });
}

/**
 * Example: Different rate limits for different endpoints
 */
const RATE_LIMITS: Record<string, RateLimitConfig> = {
  '/api/analyze': { windowMs: 60000, maxRequests: 5 },
  '/api/checkout': { windowMs: 60000, maxRequests: 20 },
  '/api/delete-account': { windowMs: 60000, maxRequests: 3 },
};

function getRateLimitForEndpoint(path: string): RateLimitConfig {
  return RATE_LIMITS[path] ?? { windowMs: 60000, maxRequests: 10 };
}

// ============================================================================
// Input Validation Example
// ============================================================================

import {
  validatePayloadSize,
  isValidUUID,
  isValidEmail,
  isNonEmptyString,
  createValidationErrorResponse,
  type ValidationLimits,
} from '../server/validation';

/**
 * Example: Validate a batch processing request
 */
interface BatchItem {
  id: string;
  content: string;
}

async function handleBatchRequest(request: Request): Promise<Response> {
  const body = await request.json();

  // Validate required fields
  if (!Array.isArray(body.items)) {
    return createValidationErrorResponse('items must be an array');
  }

  // Validate each item's ID format
  for (const item of body.items) {
    if (!isValidUUID(item.id)) {
      return createValidationErrorResponse(`Invalid ID format: ${item.id}`);
    }
    if (!isNonEmptyString(item.content)) {
      return createValidationErrorResponse('Content cannot be empty');
    }
  }

  // Validate payload size
  const limits: ValidationLimits = {
    maxItems: 50,
    maxTextLength: 10000,
    maxTotalPayloadSize: 1024 * 1024, // 1MB
  };

  const validation = validatePayloadSize(
    body.items as BatchItem[],
    (item) => item.content,
    limits
  );

  if (!validation.valid) {
    return createValidationErrorResponse(validation.error!);
  }

  // Process the validated request...
  return new Response(JSON.stringify({ success: true }));
}

/**
 * Example: Validate user registration
 */
async function handleRegistration(request: Request): Promise<Response> {
  const { email, name } = await request.json();

  // Validate email format
  if (!isValidEmail(email)) {
    return createValidationErrorResponse('Invalid email format');
  }

  // Validate name
  if (!isNonEmptyString(name)) {
    return createValidationErrorResponse('Name is required');
  }

  if (name.length > 100) {
    return createValidationErrorResponse('Name too long (max 100 characters)');
  }

  // Proceed with registration...
  return new Response(JSON.stringify({ success: true }));
}

// ============================================================================
// Placeholder functions (implement these for your app)
// ============================================================================

declare const yourAuthProvider: {
  signIn(email: string, password: string): Promise<{ user: { id: string }; session: unknown }>;
  getSession(): Promise<unknown>;
  signOut(): Promise<void>;
};

declare function fetchUserSalt(userId: string): Promise<string | null>;
declare function saveUserSalt(userId: string, salt: string): Promise<void>;
declare function getUserIdFromRequest(request: Request): Promise<string>;
declare function processRequest(request: Request): Promise<unknown>;

declare const db: {
  insert(table: string, data: Record<string, unknown>): Promise<void>;
  get(table: string, id: string): Promise<Record<string, unknown>>;
};
