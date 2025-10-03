"use strict";
/**
 * Token Validator for Backstage JWT Authentication
 *
 * Validates JWT tokens from Backstage, verifying signature and all claims.
 * Implements secure token validation with comprehensive error handling.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenValidator = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const backstage_auth_1 = require("../types/backstage-auth");
const identity_resolver_1 = require("./identity-resolver");
/**
 * Token Validator class
 * Handles JWT validation and payload extraction
 */
class TokenValidator {
    constructor(config, jwksManager) {
        this.config = config;
        this.jwksManager = jwksManager;
    }
    /**
     * Extract JWT token from Authorization header
     * @param authHeader - Authorization header value
     * @returns Extracted JWT token
     */
    extractToken(authHeader) {
        if (!authHeader) {
            throw new backstage_auth_1.AuthenticationError('MISSING_TOKEN', 'Authentication required', 401);
        }
        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
            throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Invalid authorization header format', 401);
        }
        return parts[1];
    }
    /**
     * Validate JWT token and extract authenticated user information
     * @param token - JWT token to validate
     * @returns Authenticated user context
     */
    async validateToken(token) {
        try {
            // Decode token header to get kid
            const decoded = jsonwebtoken_1.default.decode(token, { complete: true });
            if (!decoded || typeof decoded === 'string') {
                throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Invalid token format', 401);
            }
            const { header, payload } = decoded;
            if (!header.kid) {
                throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Token missing key ID', 401);
            }
            // Get signing key from JWKS
            const publicKey = await this.jwksManager.getSigningKey(header.kid);
            // Verify token signature and claims
            // Support both RSA (RS256/384/512) and Elliptic Curve (ES256/384/512) algorithms
            const verified = jsonwebtoken_1.default.verify(token, publicKey, {
                algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
                issuer: this.config.issuer,
                audience: this.config.audience,
                clockTolerance: 30, // 30 seconds clock skew tolerance
            });
            // Validate required claims
            this.validateClaims(verified);
            // Extract user information
            const user = this.extractUserInfo(verified, token);
            console.log(`[Token Validator] Successfully validated token for user: ${user.subject}`);
            return user;
        }
        catch (error) {
            if (error instanceof backstage_auth_1.AuthenticationError) {
                throw error;
            }
            // Map jwt library errors to AuthenticationError
            if (error instanceof jsonwebtoken_1.default.TokenExpiredError) {
                throw new backstage_auth_1.AuthenticationError('EXPIRED_TOKEN', 'Token has expired', 401, { expiredAt: error.expiredAt });
            }
            if (error instanceof jsonwebtoken_1.default.JsonWebTokenError) {
                throw new backstage_auth_1.AuthenticationError('INVALID_SIGNATURE', 'Invalid token signature', 401, { error: error.message });
            }
            console.error('[Token Validator] Validation error:', error);
            throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Token validation failed', 401, { error: error instanceof Error ? error.message : String(error) });
        }
    }
    /**
     * Validate all required JWT claims
     * @param payload - JWT payload to validate
     */
    validateClaims(payload) {
        const now = Math.floor(Date.now() / 1000);
        // Validate exp claim
        if (!payload.exp) {
            throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Token missing expiration claim', 401);
        }
        if (payload.exp < now) {
            throw new backstage_auth_1.AuthenticationError('EXPIRED_TOKEN', 'Token has expired', 401, { exp: payload.exp, now });
        }
        // Validate nbf claim (not before)
        if (payload.nbf && payload.nbf > now) {
            throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Token not yet valid', 401, { nbf: payload.nbf, now });
        }
        // Validate issuer claim
        if (this.config.issuer && payload.iss !== this.config.issuer) {
            throw new backstage_auth_1.AuthenticationError('INVALID_ISSUER', 'Invalid token issuer', 401, { expected: this.config.issuer, actual: payload.iss });
        }
        // Validate audience claim
        if (this.config.audience) {
            const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
            if (!audiences.includes(this.config.audience)) {
                throw new backstage_auth_1.AuthenticationError('INVALID_AUDIENCE', 'Invalid token audience', 401, { expected: this.config.audience, actual: payload.aud });
            }
        }
        // Validate subject claim
        if (!payload.sub) {
            throw new backstage_auth_1.AuthenticationError('INVALID_TOKEN', 'Token missing subject claim', 401);
        }
    }
    /**
     * Extract authenticated user information from JWT payload
     * @param payload - Validated JWT payload
     * @param token - Original JWT token
     * @returns Authenticated user context
     */
    extractUserInfo(payload, token) {
        // Get user reference from Backstage-specific claim or fallback to sub
        const userRefString = payload['backstage.io/user'] || payload.sub;
        const userRef = (0, identity_resolver_1.parseEntityRef)(userRefString);
        // Get group references
        const groupRefStrings = payload['backstage.io/groups'] || [];
        const groupRefs = groupRefStrings.map(identity_resolver_1.parseEntityRef);
        return {
            userRef,
            groupRefs,
            subject: payload.sub,
            expiresAt: payload.exp,
            payload,
            token,
        };
    }
    /**
     * Validate token from Authorization header
     * @param authHeader - Authorization header value
     * @returns Authenticated user context
     */
    async validateAuthHeader(authHeader) {
        const token = this.extractToken(authHeader);
        return this.validateToken(token);
    }
}
exports.TokenValidator = TokenValidator;
