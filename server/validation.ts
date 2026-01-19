/**
 * Input Validation Module
 * Validates request payloads for security and resource protection
 *
 * This module provides validation functions to prevent:
 * - Resource exhaustion attacks (oversized payloads)
 * - Injection attacks (invalid input formats)
 * - Denial of service (excessive array lengths)
 *
 * @license MIT
 * @see https://github.com/gemkuru/bedrock-security
 */

// ============================================================================
// Types
// ============================================================================

export interface ValidationResult {
  valid: boolean;
  error?: string;
}

export interface ValidationLimits {
  /** Maximum number of items in a batch (default: 25) */
  maxItems?: number;
  /** Maximum sub-items per item (default: 100) */
  maxSubItemsPerItem?: number;
  /** Maximum length of a single text field (default: 10000) */
  maxTextLength?: number;
  /** Maximum total payload size in bytes (default: 1MB) */
  maxTotalPayloadSize?: number;
}

// ============================================================================
// Default Limits
// ============================================================================

/**
 * Default size limits - customize for your use case
 * These values are intentionally conservative for security
 */
export const DEFAULT_LIMITS: Required<ValidationLimits> = {
  maxItems: 25,
  maxSubItemsPerItem: 100,
  maxTextLength: 10000,
  maxTotalPayloadSize: 1 * 1024 * 1024, // 1MB
};

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validates a UUID format (v4)
 * Use for validating IDs in API requests
 */
export function isValidUUID(value: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(value);
}

/**
 * Validates an email format
 * Basic validation - for production, consider additional verification
 */
export function isValidEmail(value: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(value) && value.length <= 254;
}

/**
 * Validates that a value is a non-empty string
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Validates that a value is a positive integer
 */
export function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0;
}

/**
 * Validates payload size and structure to prevent resource exhaustion
 *
 * @param items - Array of items to validate
 * @param getTextContent - Function to extract text content from an item for size calculation
 * @param limits - Optional custom limits
 */
export function validatePayloadSize<T>(
  items: T[],
  getTextContent: (item: T) => string | string[],
  limits: ValidationLimits = {}
): ValidationResult {
  const {
    maxItems,
    maxSubItemsPerItem,
    maxTextLength,
    maxTotalPayloadSize,
  } = { ...DEFAULT_LIMITS, ...limits };

  // Check number of items
  if (items.length > maxItems) {
    return {
      valid: false,
      error: `Too many items: ${items.length} (max: ${maxItems})`,
    };
  }

  let totalSize = 0;

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const content = getTextContent(item);

    // Handle array of strings (e.g., messages in a chunk)
    if (Array.isArray(content)) {
      if (content.length > maxSubItemsPerItem) {
        return {
          valid: false,
          error: `Item ${i} has too many sub-items: ${content.length} (max: ${maxSubItemsPerItem})`,
        };
      }

      for (let j = 0; j < content.length; j++) {
        const text = content[j];
        if (text.length > maxTextLength) {
          return {
            valid: false,
            error: `Text in item ${i} exceeds length limit (max: ${maxTextLength} chars)`,
          };
        }
        totalSize += text.length;
      }
    } else {
      // Handle single string
      if (content.length > maxTextLength) {
        return {
          valid: false,
          error: `Item ${i} exceeds length limit (max: ${maxTextLength} chars)`,
        };
      }
      totalSize += content.length;
    }
  }

  // Check total payload size
  if (totalSize > maxTotalPayloadSize) {
    return {
      valid: false,
      error: `Total payload too large (max: ${Math.floor(maxTotalPayloadSize / 1024 / 1024)}MB)`,
    };
  }

  return { valid: true };
}

/**
 * Validates that a value is in an allowed list (whitelist validation)
 * Use for validating enum-like values, model names, etc.
 */
export function isAllowedValue<T>(value: T, allowedValues: Set<T>): boolean {
  return allowedValues.has(value);
}

/**
 * Sanitizes a string for safe logging (removes potential injection characters)
 * Note: This is for logging only, not for preventing XSS or SQL injection
 */
export function sanitizeForLogging(value: string, maxLength: number = 100): string {
  return value
    .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
    .slice(0, maxLength);
}

/**
 * Validates base64 format
 * Use for validating encrypted data, file uploads, etc.
 */
export function isValidBase64(value: string): boolean {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(value);
}

/**
 * Creates a validation error response
 */
export function createValidationErrorResponse(error: string): Response {
  return new Response(
    JSON.stringify({ error, code: 'VALIDATION_ERROR' }),
    {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}
