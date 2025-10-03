/**
 * Authorization Middleware for Backstage JWT
 *
 * Middleware for checking user access rights based on allowed users and groups.
 * Enforces authorization policies for protected resources.
 */

import type { Request, Response, NextFunction } from 'express';
import type { Socket } from 'socket.io';
import type { BackstageAuthConfig, AuthenticatedUser, AuthorizationResult, AuthErrorType } from '../types/backstage-auth';
import { AuthenticationError } from '../types/backstage-auth';
import { authorizeUser, stringifyEntityRef } from '../services/identity-resolver';

// Extend Socket.IO Socket to include authenticated user
interface AuthenticatedSocket extends Socket {
  user?: AuthenticatedUser;
}

/**
 * Authorization Manager
 * Handles authorization checks for authenticated users
 */
export class AuthorizationManager {
  private config: BackstageAuthConfig;

  constructor(config: BackstageAuthConfig) {
    this.config = config;

    console.log('[Authorization Manager] Initialized with config:', {
      allowedUsers: config.allowedUsers?.length || 0,
      allowedGroups: config.allowedGroups?.length || 0,
    });
  }

  /**
   * Create Express authorization middleware
   * @returns Express middleware function
   */
  createExpressMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const path = req.path;

      // Skip authorization for health checks and public endpoints
      if (path === '/health' || path === '/api/health') {
        return next();
      }

      try {
        // Check if user is authenticated
        if (!req.user) {
          if (this.config.requireAuth) {
            throw new AuthenticationError(
              'MISSING_TOKEN' as AuthErrorType,
              'Authentication required',
              401
            );
          }
          return next(); // No auth required, allow
        }

        // Authorize user
        const result = this.authorizeRequest(req.user, req);

        if (!result.allowed) {
          console.warn(`[Authorization] Denied access for ${req.user.subject}: ${result.reason}`);

          throw new AuthenticationError(
            'AUTHORIZATION_FAILED' as AuthErrorType,
            'Access denied',
            403,
            { reason: result.reason }
          );
        }

        console.log(`[Authorization] Allowed access for ${req.user.subject}: ${result.reason}`);
        next();
      } catch (error) {
        if (error instanceof AuthenticationError) {
          res.status(error.statusCode).json({
            error: error.message,
            type: error.type,
          });
          return;
        }

        console.error('[Authorization Middleware] Unexpected error:', error);

        res.status(500).json({
          error: 'Authorization failed',
        });
      }
    };
  }

  /**
   * Create WebSocket authorization handler
   * @returns WebSocket middleware function
   */
  createWebSocketMiddleware() {
    return async (socket: AuthenticatedSocket, next: (err?: Error) => void): Promise<void> => {
      try {
        // Check if user is authenticated
        if (!socket.user) {
          if (this.config.requireAuth) {
            return next(new Error('Authentication required'));
          }
          return next(); // No auth required, allow
        }

        // Authorize user
        const result = this.authorizeSocket(socket.user, socket);

        if (!result.allowed) {
          console.warn(`[WS Authorization] Denied access for ${socket.user.subject}: ${result.reason}`);
          return next(new Error('Access denied'));
        }

        console.log(`[WS Authorization] Allowed access for ${socket.user.subject}: ${result.reason}`);
        next();
      } catch (error) {
        console.error('[WS Authorization Middleware] Unexpected error:', error);
        next(new Error('Authorization failed'));
      }
    };
  }

  /**
   * Authorize HTTP request
   * @param user - Authenticated user
   * @param req - Express request
   * @returns Authorization result
   */
  private authorizeRequest(user: AuthenticatedUser, req: Request): AuthorizationResult {
    // Use standard authorization logic
    const result = authorizeUser(user, this.config);

    if (!result.allowed) {
      return result;
    }

    // Additional resource-specific authorization can be added here
    // For example, checking terminal ownership for /api/terminals/:id

    return result;
  }

  /**
   * Authorize WebSocket connection
   * @param user - Authenticated user
   * @param socket - WebSocket socket
   * @returns Authorization result
   */
  private authorizeSocket(user: AuthenticatedUser, socket: AuthenticatedSocket): AuthorizationResult {
    // Use standard authorization logic
    const result = authorizeUser(user, this.config);

    if (!result.allowed) {
      return result;
    }

    // Additional socket-specific authorization can be added here

    return result;
  }

  /**
   * Check if user can access specific terminal
   * @param user - Authenticated user
   * @param terminalId - Terminal ID
   * @param terminalOwner - Terminal owner user ref
   * @returns True if user can access terminal
   */
  canAccessTerminal(user: AuthenticatedUser, terminalId: string, terminalOwner?: string): boolean {
    // User can access their own terminals
    if (terminalOwner) {
      const userRefString = stringifyEntityRef(user.userRef);
      if (userRefString === terminalOwner) {
        return true;
      }
    }

    // Additional logic can be added here, e.g., admins can access all terminals

    return !terminalOwner; // If no owner, allow (for backward compatibility)
  }

  /**
   * Check if user has admin privileges
   * @param user - Authenticated user
   * @returns True if user is admin
   */
  isAdmin(user: AuthenticatedUser): boolean {
    // Check if user is in admin group
    const adminGroups = ['group:default/admins', 'group:default/admin'];

    return user.groupRefs.some(groupRef => {
      const groupRefString = stringifyEntityRef(groupRef);
      return adminGroups.includes(groupRefString);
    });
  }

  /**
   * Get user permissions summary
   * @param user - Authenticated user
   * @returns Permissions summary
   */
  getUserPermissions(user: AuthenticatedUser): {
    userRef: string;
    groups: string[];
    isAdmin: boolean;
    authorized: boolean;
  } {
    const userRefString = stringifyEntityRef(user.userRef);
    const groups = user.groupRefs.map(stringifyEntityRef);
    const isAdmin = this.isAdmin(user);
    const authResult = authorizeUser(user, this.config);

    return {
      userRef: userRefString,
      groups,
      isAdmin,
      authorized: authResult.allowed,
    };
  }
}
