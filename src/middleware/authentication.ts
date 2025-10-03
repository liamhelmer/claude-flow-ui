/**
 * Authentication Middleware for Backstage JWT
 *
 * Express middleware and WebSocket handlers for JWT authentication.
 * Attaches authenticated user context to requests and socket connections.
 */

import type { Request, Response, NextFunction } from 'express';
import type { Socket } from 'socket.io';
import type { BackstageAuthConfig, AuthenticatedUser, AuditLogEntry, AuthErrorType } from '../types/backstage-auth';
import { AuthenticationError } from '../types/backstage-auth';
import { TokenValidator } from '../services/token-validator';
import { JWKSManager } from '../services/jwks-manager';

// Extend Express Request to include authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

// Extend Socket.IO Socket to include authenticated user
interface AuthenticatedSocket extends Socket {
  user?: AuthenticatedUser;
}

/**
 * Audit logger for security events
 */
class AuditLogger {
  private logs: AuditLogEntry[] = [];
  private maxLogs = 10000;

  log(entry: Omit<AuditLogEntry, 'timestamp'>): void {
    const fullEntry: AuditLogEntry = {
      ...entry,
      timestamp: new Date(),
    };

    this.logs.push(fullEntry);

    // Keep only recent logs
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    // Console log for important events
    const logLevel = entry.success ? 'info' : 'warn';
    console[logLevel](`[Audit] ${entry.event}: ${entry.userRef || 'anonymous'} - ${entry.success ? 'SUCCESS' : 'FAILURE'}`);
  }

  getRecentLogs(count: number = 100): AuditLogEntry[] {
    return this.logs.slice(-count);
  }
}

/**
 * Rate limiter for authentication attempts
 */
class RateLimiter {
  private attempts = new Map<string, { count: number; windowStart: number }>();
  private config: BackstageAuthConfig;

  constructor(config: BackstageAuthConfig) {
    this.config = config;

    // Clean up old entries periodically
    setInterval(() => this.cleanup(), 60000); // Every minute
  }

  /**
   * Check if request should be rate limited
   * @param identifier - User identifier (IP or user ref)
   * @returns True if rate limit exceeded
   */
  checkLimit(identifier: string): boolean {
    const now = Date.now();
    const window = this.config.rateLimitWindow || 900000; // 15 minutes default
    const maxRequests = this.config.rateLimitMax || 100;

    const entry = this.attempts.get(identifier);

    if (!entry || now > entry.windowStart + window) {
      // New window
      this.attempts.set(identifier, { count: 1, windowStart: now });
      return false;
    }

    // Increment count in current window
    entry.count++;

    if (entry.count > maxRequests) {
      return true; // Rate limit exceeded
    }

    return false;
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    const window = this.config.rateLimitWindow || 900000;

    for (const [identifier, entry] of this.attempts.entries()) {
      if (now > entry.windowStart + window) {
        this.attempts.delete(identifier);
      }
    }
  }
}

/**
 * Authentication Manager
 * Central manager for authentication operations
 */
export class AuthenticationManager {
  private config: BackstageAuthConfig;
  private jwksManager: JWKSManager;
  private tokenValidator: TokenValidator;
  private auditLogger: AuditLogger;
  private rateLimiter: RateLimiter;

  constructor(config: BackstageAuthConfig) {
    this.config = config;
    this.jwksManager = new JWKSManager(config);
    this.tokenValidator = new TokenValidator(config, this.jwksManager);
    this.auditLogger = new AuditLogger();
    this.rateLimiter = new RateLimiter(config);

    console.log('[Auth Manager] Initialized with config:', {
      backstageUrl: config.backstageUrl,
      requireAuth: config.requireAuth,
      issuer: config.issuer,
      audience: config.audience,
    });
  }

  /**
   * Create Express authentication middleware
   * @returns Express middleware function
   */
  createExpressMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const path = req.path;
      const ipAddress = req.ip || req.socket.remoteAddress || 'unknown';

      // Skip authentication for health checks and public endpoints
      if (path === '/health' || path === '/api/health') {
        return next();
      }

      try {
        const authHeader = req.headers.authorization;

        // If auth not required and no token provided, skip
        if (!this.config.requireAuth && !authHeader) {
          return next();
        }

        // Validate token
        let user;
        try {
          user = await this.tokenValidator.validateAuthHeader(authHeader);
        } catch (authError) {
          // Only rate limit FAILED authentication attempts
          // Check rate limit by IP for failed attempts
          if (this.rateLimiter.checkLimit(ipAddress)) {
            this.auditLogger.log({
              event: 'rate_limit_exceeded',
              ipAddress,
              details: { path },
              success: false,
            });

            throw new AuthenticationError(
              'RATE_LIMIT_EXCEEDED' as AuthErrorType,
              'Too many requests',
              429
            );
          }

          // Re-throw the original auth error
          throw authError;
        }

        // Attach user to request
        req.user = user;

        this.auditLogger.log({
          event: 'authentication_success',
          userRef: user.subject,
          ipAddress,
          details: { path, method: req.method },
          success: true,
        });

        next();
      } catch (error) {
        if (error instanceof AuthenticationError) {
          this.auditLogger.log({
            event: 'authentication_failure',
            ipAddress,
            details: { path, error: error.type },
            success: false,
          });

          res.status(error.statusCode).json({
            error: error.message,
            type: error.type,
          });
          return;
        }

        console.error('[Auth Middleware] Unexpected error:', error);

        this.auditLogger.log({
          event: 'authentication_error',
          ipAddress,
          details: { path, error: String(error) },
          success: false,
        });

        res.status(500).json({
          error: 'Authentication failed',
        });
      }
    };
  }

  /**
   * Create WebSocket authentication handler
   * @returns WebSocket middleware function
   */
  createWebSocketMiddleware() {
    return async (socket: AuthenticatedSocket, next: (err?: Error) => void): Promise<void> => {
      const ipAddress = socket.handshake.address || 'unknown';

      try {
        // Get token from handshake auth or query
        const token = socket.handshake.auth?.token || socket.handshake.query?.token as string;

        // If auth not required and no token provided, skip
        if (!this.config.requireAuth && !token) {
          return next();
        }

        if (!token) {
          this.auditLogger.log({
            event: 'ws_authentication_failure',
            ipAddress,
            details: { socketId: socket.id, reason: 'missing_token' },
            success: false,
          });

          return next(new Error('Authentication required'));
        }

        // Validate token
        let user: AuthenticatedUser;
        try {
          user = await this.tokenValidator.validateToken(token);
        } catch (authError) {
          // Only rate limit FAILED authentication attempts
          if (this.rateLimiter.checkLimit(ipAddress)) {
            this.auditLogger.log({
              event: 'ws_rate_limit_exceeded',
              ipAddress,
              details: { socketId: socket.id },
              success: false,
            });

            return next(new Error('Too many requests'));
          }

          // Re-throw the original auth error
          throw authError;
        }

        // Attach user to socket
        socket.user = user;

        this.auditLogger.log({
          event: 'ws_authentication_success',
          userRef: user.subject,
          ipAddress,
          details: { socketId: socket.id },
          success: true,
        });

        next();
      } catch (error) {
        if (error instanceof AuthenticationError) {
          this.auditLogger.log({
            event: 'ws_authentication_failure',
            ipAddress,
            details: { socketId: socket.id, error: error.type },
            success: false,
          });

          return next(new Error(error.message));
        }

        console.error('[WS Auth Middleware] Unexpected error:', error);

        this.auditLogger.log({
          event: 'ws_authentication_error',
          ipAddress,
          details: { socketId: socket.id, error: String(error) },
          success: false,
        });

        next(new Error('Authentication failed'));
      }
    };
  }

  /**
   * Get recent audit logs
   */
  getAuditLogs(count: number = 100): AuditLogEntry[] {
    return this.auditLogger.getRecentLogs(count);
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    this.jwksManager.destroy();
    console.log('[Auth Manager] Destroyed');
  }
}

// ============================================================================
// FACTORY FUNCTIONS FOR EXPRESS INTEGRATION
// ============================================================================

/**
 * Create Express authentication middleware
 */
export function createAuthenticationMiddleware(config: BackstageAuthConfig) {
  const manager = new AuthenticationManager(config);
  return manager.createExpressMiddleware();
}

/**
 * Create WebSocket authentication handler
 */
export function createWebSocketAuthHandler(config: BackstageAuthConfig) {
  const jwksManager = new JWKSManager(config);
  const tokenValidator = new TokenValidator(config, jwksManager);

  return async (token: string): Promise<{ authenticated: boolean; user?: AuthenticatedUser; error?: string; message?: string }> => {
    try {
      console.log('[WebSocket Auth Handler] Validating token...');
      const user = await tokenValidator.validateToken(token);
      console.log('[WebSocket Auth Handler] Token validated successfully, subject:', user.subject);
      console.log('[WebSocket Auth Handler] User identity:', user.userRef);

      // Import identity resolver for authorization check
      const { authorizeUser } = require('../services/identity-resolver');
      const authResult = authorizeUser(user, config);
      console.log('[WebSocket Auth Handler] Authorization result:', authResult.allowed, authResult.reason);

      if (!authResult.allowed) {
        console.warn('[WebSocket Auth Handler] Authorization failed:', authResult.reason);
        return {
          authenticated: false,
          error: 'AUTHORIZATION_FAILED',
          message: authResult.reason
        };
      }

      console.log('[WebSocket Auth Handler] ✅ Authentication successful for:', authResult.user.userRef);
      return {
        authenticated: true,
        user: authResult.user
      };
    } catch (error) {
      // Enhanced error logging
      console.error('[WebSocket Auth Handler] ❌ Authentication error:', error);
      console.error('[WebSocket Auth Handler] Error type:', error?.constructor?.name);
      console.error('[WebSocket Auth Handler] Error message:', error instanceof Error ? error.message : String(error));
      console.error('[WebSocket Auth Handler] Error stack:', error instanceof Error ? error.stack : 'N/A');

      if (error instanceof AuthenticationError) {
        console.error('[WebSocket Auth Handler] AuthenticationError type:', error.type);
        return {
          authenticated: false,
          error: error.type,
          message: error.message
        };
      }

      return {
        authenticated: false,
        error: 'AUTHENTICATION_ERROR',
        message: error instanceof Error ? error.message : 'Authentication failed'
      };
    }
  };
}
