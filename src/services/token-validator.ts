/**
 * Token Validator for Backstage JWT Authentication
 *
 * Validates JWT tokens from Backstage, verifying signature and all claims.
 * Implements secure token validation with comprehensive error handling.
 */

import jwt from 'jsonwebtoken';
import type { BackstageAuthConfig, BackstageJWTPayload, AuthenticatedUser, AuthErrorType } from '../types/backstage-auth';
import { AuthenticationError } from '../types/backstage-auth';
import { JWKSManager } from './jwks-manager';
import { parseEntityRef } from './identity-resolver';

/**
 * Token Validator class
 * Handles JWT validation and payload extraction
 */
export class TokenValidator {
  private jwksManager: JWKSManager;
  private config: BackstageAuthConfig;

  constructor(config: BackstageAuthConfig, jwksManager: JWKSManager) {
    this.config = config;
    this.jwksManager = jwksManager;
  }

  /**
   * Extract JWT token from Authorization header
   * @param authHeader - Authorization header value
   * @returns Extracted JWT token
   */
  extractToken(authHeader: string | undefined): string {
    if (!authHeader) {
      throw new AuthenticationError(
        'MISSING_TOKEN' as AuthErrorType,
        'Authentication required',
        401
      );
    }

    const parts = authHeader.split(' ');

    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      throw new AuthenticationError(
        'INVALID_TOKEN' as AuthErrorType,
        'Invalid authorization header format',
        401
      );
    }

    return parts[1];
  }

  /**
   * Validate JWT token and extract authenticated user information
   * @param token - JWT token to validate
   * @returns Authenticated user context
   */
  async validateToken(token: string): Promise<AuthenticatedUser> {
    try {
      // Decode token header to get kid
      const decoded = jwt.decode(token, { complete: true });

      if (!decoded || typeof decoded === 'string') {
        throw new AuthenticationError(
          'INVALID_TOKEN' as AuthErrorType,
          'Invalid token format',
          401
        );
      }

      const { header, payload } = decoded;

      if (!header.kid) {
        throw new AuthenticationError(
          'INVALID_TOKEN' as AuthErrorType,
          'Token missing key ID',
          401
        );
      }

      // Get signing key from JWKS
      const publicKey = await this.jwksManager.getSigningKey(header.kid);

      // Verify token signature and claims
      // Support both RSA (RS256/384/512) and Elliptic Curve (ES256/384/512) algorithms
      const verified = jwt.verify(token, publicKey, {
        algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockTolerance: 30, // 30 seconds clock skew tolerance
      }) as BackstageJWTPayload;

      // Validate required claims
      this.validateClaims(verified);

      // Extract user information
      const user = this.extractUserInfo(verified, token);

      console.log(`[Token Validator] Successfully validated token for user: ${user.subject}`);

      return user;
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      // Map jwt library errors to AuthenticationError
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthenticationError(
          'EXPIRED_TOKEN' as AuthErrorType,
          'Token has expired',
          401,
          { expiredAt: error.expiredAt }
        );
      }

      if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthenticationError(
          'INVALID_SIGNATURE' as AuthErrorType,
          'Invalid token signature',
          401,
          { error: error.message }
        );
      }

      console.error('[Token Validator] Validation error:', error);
      throw new AuthenticationError(
        'INVALID_TOKEN' as AuthErrorType,
        'Token validation failed',
        401,
        { error: error instanceof Error ? error.message : String(error) }
      );
    }
  }

  /**
   * Validate all required JWT claims
   * @param payload - JWT payload to validate
   */
  private validateClaims(payload: BackstageJWTPayload): void {
    const now = Math.floor(Date.now() / 1000);

    // Validate exp claim
    if (!payload.exp) {
      throw new AuthenticationError(
        'INVALID_TOKEN' as AuthErrorType,
        'Token missing expiration claim',
        401
      );
    }

    if (payload.exp < now) {
      throw new AuthenticationError(
        'EXPIRED_TOKEN' as AuthErrorType,
        'Token has expired',
        401,
        { exp: payload.exp, now }
      );
    }

    // Validate nbf claim (not before)
    if (payload.nbf && payload.nbf > now) {
      throw new AuthenticationError(
        'INVALID_TOKEN' as AuthErrorType,
        'Token not yet valid',
        401,
        { nbf: payload.nbf, now }
      );
    }

    // Validate issuer claim
    if (this.config.issuer && payload.iss !== this.config.issuer) {
      throw new AuthenticationError(
        'INVALID_ISSUER' as AuthErrorType,
        'Invalid token issuer',
        401,
        { expected: this.config.issuer, actual: payload.iss }
      );
    }

    // Validate audience claim
    if (this.config.audience) {
      const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

      if (!audiences.includes(this.config.audience)) {
        throw new AuthenticationError(
          'INVALID_AUDIENCE' as AuthErrorType,
          'Invalid token audience',
          401,
          { expected: this.config.audience, actual: payload.aud }
        );
      }
    }

    // Validate subject claim
    if (!payload.sub) {
      throw new AuthenticationError(
        'INVALID_TOKEN' as AuthErrorType,
        'Token missing subject claim',
        401
      );
    }
  }

  /**
   * Extract authenticated user information from JWT payload
   * @param payload - Validated JWT payload
   * @param token - Original JWT token
   * @returns Authenticated user context
   */
  private extractUserInfo(payload: BackstageJWTPayload, token: string): AuthenticatedUser {
    // Get user reference from Backstage-specific claim or fallback to sub
    const userRefString = payload['backstage.io/user'] || payload.sub;
    const userRef = parseEntityRef(userRefString);

    // Get group references
    const groupRefStrings = payload['backstage.io/groups'] || [];
    const groupRefs = groupRefStrings.map(parseEntityRef);

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
  async validateAuthHeader(authHeader: string | undefined): Promise<AuthenticatedUser> {
    const token = this.extractToken(authHeader);
    return this.validateToken(token);
  }
}
