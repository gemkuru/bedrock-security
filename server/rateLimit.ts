/**
 * Rate Limiting Module
 * Simple in-memory rate limiter for serverless functions
 *
 * Note: This is per-worker-instance, so it won't be perfectly accurate
 * across multiple workers. For production at scale, consider using
 * Redis (e.g., Upstash) for distributed rate limiting.
 *
 * @license MIT
 * @see https://github.com/gemkuru/bedrock-security
 */

// ============================================================================
// Types
// ============================================================================

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  headers: Record<string, string>;
}

export interface RateLimitConfig {
  /** Time window in milliseconds (default: 60000 = 1 minute) */
  windowMs?: number;
  /** Maximum requests per window (default: 10) */
  maxRequests?: number;
}

// ============================================================================
// Configuration
// ============================================================================

// In-memory store (per worker instance)
const rateLimitStore = new Map<string, RateLimitEntry>();

// Default configuration - customize via environment or constructor
const DEFAULT_WINDOW_MS = 60 * 1000; // 1 minute
const DEFAULT_MAX_REQUESTS = 10; // 10 requests per minute

// Cleanup old entries periodically to prevent memory leaks
const CLEANUP_INTERVAL_MS = 60 * 1000;
let lastCleanup = Date.now();

// ============================================================================
// Internal Functions
// ============================================================================

function cleanupOldEntries(): void {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) {
    return;
  }

  lastCleanup = now;
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(key);
    }
  }
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Check and update rate limit for an identifier (usually user ID or IP)
 *
 * @param identifier - Unique identifier for the client (user ID, IP, API key, etc.)
 * @param config - Optional configuration overrides
 * @returns Rate limit result with allowed status and headers
 */
export function checkRateLimit(
  identifier: string,
  config: RateLimitConfig = {}
): RateLimitResult {
  const windowMs = config.windowMs ?? DEFAULT_WINDOW_MS;
  const maxRequests = config.maxRequests ?? DEFAULT_MAX_REQUESTS;

  // Run cleanup opportunistically
  cleanupOldEntries();

  const now = Date.now();
  const key = `rl:${identifier}`;

  let entry = rateLimitStore.get(key);

  if (!entry || now > entry.resetAt) {
    // Create new window
    entry = {
      count: 1,
      resetAt: now + windowMs,
    };
    rateLimitStore.set(key, entry);
  } else {
    // Increment existing window
    entry.count++;
  }

  const remaining = Math.max(0, maxRequests - entry.count);
  const allowed = entry.count <= maxRequests;

  return {
    allowed,
    remaining,
    resetAt: entry.resetAt,
    headers: {
      'X-RateLimit-Limit': String(maxRequests),
      'X-RateLimit-Remaining': String(remaining),
      'X-RateLimit-Reset': String(Math.ceil(entry.resetAt / 1000)),
    },
  };
}

/**
 * Get rate limit headers without incrementing the counter
 * Useful for adding headers to successful responses
 *
 * @param identifier - Unique identifier for the client
 * @param config - Optional configuration overrides
 */
export function getRateLimitHeaders(
  identifier: string,
  config: RateLimitConfig = {}
): Record<string, string> {
  const windowMs = config.windowMs ?? DEFAULT_WINDOW_MS;
  const maxRequests = config.maxRequests ?? DEFAULT_MAX_REQUESTS;

  const key = `rl:${identifier}`;
  const entry = rateLimitStore.get(key);

  if (!entry || Date.now() > entry.resetAt) {
    return {
      'X-RateLimit-Limit': String(maxRequests),
      'X-RateLimit-Remaining': String(maxRequests),
      'X-RateLimit-Reset': String(Math.ceil((Date.now() + windowMs) / 1000)),
    };
  }

  const remaining = Math.max(0, maxRequests - entry.count);

  return {
    'X-RateLimit-Limit': String(maxRequests),
    'X-RateLimit-Remaining': String(remaining),
    'X-RateLimit-Reset': String(Math.ceil(entry.resetAt / 1000)),
  };
}

/**
 * Reset rate limit for a specific identifier
 * Useful for testing or administrative overrides
 */
export function resetRateLimit(identifier: string): void {
  const key = `rl:${identifier}`;
  rateLimitStore.delete(key);
}

/**
 * Clear all rate limit entries
 * Useful for testing
 */
export function clearAllRateLimits(): void {
  rateLimitStore.clear();
}

/**
 * Create a rate-limited response helper
 * Returns a 429 response with appropriate headers
 */
export function createRateLimitResponse(result: RateLimitResult): Response {
  return new Response(
    JSON.stringify({
      error: 'Too many requests',
      retryAfter: Math.ceil((result.resetAt - Date.now()) / 1000),
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        ...result.headers,
        'Retry-After': String(Math.ceil((result.resetAt - Date.now()) / 1000)),
      },
    }
  );
}
