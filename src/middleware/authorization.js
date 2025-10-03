"use strict";
/**
 * Authorization Middleware for Backstage JWT
 *
 * Middleware for checking user access rights based on allowed users and groups.
 * Enforces authorization policies for protected resources.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthorizationManager = void 0;
const backstage_auth_1 = require("../types/backstage-auth");
const identity_resolver_1 = require("../services/identity-resolver");
/**
 * Authorization Manager
 * Handles authorization checks for authenticated users
 */
class AuthorizationManager {
    constructor(config) {
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
        return async (req, res, next) => {
            const path = req.path;
            // Skip authorization for health checks and public endpoints
            if (path === '/health' || path === '/api/health') {
                return next();
            }
            try {
                // Check if user is authenticated
                if (!req.user) {
                    if (this.config.requireAuth) {
                        throw new backstage_auth_1.AuthenticationError('MISSING_TOKEN', 'Authentication required', 401);
                    }
                    return next(); // No auth required, allow
                }
                // Authorize user
                const result = this.authorizeRequest(req.user, req);
                if (!result.allowed) {
                    console.warn(`[Authorization] Denied access for ${req.user.subject}: ${result.reason}`);
                    throw new backstage_auth_1.AuthenticationError('AUTHORIZATION_FAILED', 'Access denied', 403, { reason: result.reason });
                }
                console.log(`[Authorization] Allowed access for ${req.user.subject}: ${result.reason}`);
                next();
            }
            catch (error) {
                if (error instanceof backstage_auth_1.AuthenticationError) {
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
        return async (socket, next) => {
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
            }
            catch (error) {
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
    authorizeRequest(user, req) {
        // Use standard authorization logic
        const result = (0, identity_resolver_1.authorizeUser)(user, this.config);
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
    authorizeSocket(user, socket) {
        // Use standard authorization logic
        const result = (0, identity_resolver_1.authorizeUser)(user, this.config);
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
    canAccessTerminal(user, terminalId, terminalOwner) {
        // User can access their own terminals
        if (terminalOwner) {
            const userRefString = (0, identity_resolver_1.stringifyEntityRef)(user.userRef);
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
    isAdmin(user) {
        // Check if user is in admin group
        const adminGroups = ['group:default/admins', 'group:default/admin'];
        return user.groupRefs.some(groupRef => {
            const groupRefString = (0, identity_resolver_1.stringifyEntityRef)(groupRef);
            return adminGroups.includes(groupRefString);
        });
    }
    /**
     * Get user permissions summary
     * @param user - Authenticated user
     * @returns Permissions summary
     */
    getUserPermissions(user) {
        const userRefString = (0, identity_resolver_1.stringifyEntityRef)(user.userRef);
        const groups = user.groupRefs.map(identity_resolver_1.stringifyEntityRef);
        const isAdmin = this.isAdmin(user);
        const authResult = (0, identity_resolver_1.authorizeUser)(user, this.config);
        return {
            userRef: userRefString,
            groups,
            isAdmin,
            authorized: authResult.allowed,
        };
    }
}
exports.AuthorizationManager = AuthorizationManager;
