/**
 * Type definitions for Backstage JWT authentication
 *
 * These types define the configuration, JWT payload structure, and entity references
 * used for Backstage authentication and authorization.
 */
/**
 * Configuration options for Backstage JWT authentication
 */
export interface BackstageAuthConfig {
    /** Backstage base URL (e.g., https://backstage.example.com) */
    backstageUrl: string;
    /** Path to JWKS endpoint (default: /api/auth/.well-known/jwks.json) */
    jwksPath?: string;
    /** Whether authentication is required (default: false) */
    requireAuth?: boolean;
    /** Expected JWT issuer (must match token iss claim) */
    issuer?: string;
    /** Expected JWT audience (must match token aud claim) */
    audience?: string;
    /** List of allowed user entity references (e.g., user:default/john.doe) */
    allowedUsers?: string[];
    /** List of allowed group entity references (e.g., group:default/admins) */
    allowedGroups?: string[];
    /** JWKS cache TTL in milliseconds (default: 3600000 = 1 hour) */
    jwksCacheTTL?: number;
    /** Maximum retry attempts for JWKS fetch (default: 3) */
    maxRetryAttempts?: number;
    /** Rate limit: max requests per window (default: 100) */
    rateLimitMax?: number;
    /** Rate limit: window duration in milliseconds (default: 900000 = 15 minutes) */
    rateLimitWindow?: number;
}
/**
 * Backstage entity reference format
 * Format: [kind]:[namespace]/[name]
 * Examples: user:default/john.doe, group:default/admins
 */
export interface BackstageEntityRef {
    kind: string;
    namespace: string;
    name: string;
}
/**
 * JWT payload structure from Backstage tokens
 */
export interface BackstageJWTPayload {
    /** Subject claim - user entity reference */
    sub: string;
    /** Issuer claim - must match configured issuer */
    iss?: string;
    /** Audience claim - must match configured audience */
    aud?: string | string[];
    /** Expiration time (Unix timestamp in seconds) */
    exp: number;
    /** Not before time (Unix timestamp in seconds) */
    nbf?: number;
    /** Issued at time (Unix timestamp in seconds) */
    iat?: number;
    /** User entity reference (user:namespace/name) */
    'backstage.io/user'?: string;
    /** Group entity references (array of group:namespace/name) */
    'backstage.io/groups'?: string[];
    /** Entity ownership claims */
    'backstage.io/claims'?: {
        entities?: string[];
        ownership?: string[];
    };
    /** Additional custom claims */
    [key: string]: unknown;
}
/**
 * Authenticated user context attached to Express requests
 */
export interface AuthenticatedUser {
    /** User entity reference */
    userRef: BackstageEntityRef;
    /** Group entity references */
    groupRefs: BackstageEntityRef[];
    /** JWT subject claim */
    subject: string;
    /** JWT expiration timestamp */
    expiresAt: number;
    /** Full JWT payload */
    payload: BackstageJWTPayload;
    /** Raw JWT token */
    token: string;
}
/**
 * Authorization result with detailed information
 */
export interface AuthorizationResult {
    /** Whether authorization was successful */
    allowed: boolean;
    /** Reason for authorization decision */
    reason: string;
    /** User information if authenticated */
    user?: AuthenticatedUser;
}
/**
 * Rate limit tracking per user
 */
export interface RateLimitInfo {
    /** Number of requests made in current window */
    count: number;
    /** Window start time (Unix timestamp in milliseconds) */
    windowStart: number;
    /** Whether rate limit is exceeded */
    exceeded: boolean;
}
/**
 * Audit log entry for security events
 */
export interface AuditLogEntry {
    /** Timestamp of the event */
    timestamp: Date;
    /** Event type (auth_success, auth_failure, rate_limit, etc.) */
    event: string;
    /** User entity reference (if authenticated) */
    userRef?: string;
    /** IP address of the client */
    ipAddress?: string;
    /** Additional event details */
    details: Record<string, unknown>;
    /** Whether the action was successful */
    success: boolean;
}
/**
 * JWKS cache entry
 */
export interface JWKSCacheEntry {
    /** Cached JWKS data */
    keys: unknown[];
    /** Cache timestamp (Unix timestamp in milliseconds) */
    cachedAt: number;
    /** Cache expiration timestamp (Unix timestamp in milliseconds) */
    expiresAt: number;
}
/**
 * Authentication error types
 */
export declare enum AuthErrorType {
    INVALID_TOKEN = "INVALID_TOKEN",
    EXPIRED_TOKEN = "EXPIRED_TOKEN",
    INVALID_SIGNATURE = "INVALID_SIGNATURE",
    INVALID_ISSUER = "INVALID_ISSUER",
    INVALID_AUDIENCE = "INVALID_AUDIENCE",
    MISSING_TOKEN = "MISSING_TOKEN",
    JWKS_FETCH_FAILED = "JWKS_FETCH_FAILED",
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED",
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
}
/**
 * Custom authentication error class
 */
export declare class AuthenticationError extends Error {
    type: AuthErrorType;
    statusCode: number;
    details?: Record<string, unknown>;
    constructor(type: AuthErrorType, message: string, statusCode?: number, details?: Record<string, unknown>);
}
