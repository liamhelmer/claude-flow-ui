"use strict";
/**
 * Type definitions for Backstage JWT authentication
 *
 * These types define the configuration, JWT payload structure, and entity references
 * used for Backstage authentication and authorization.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthenticationError = exports.AuthErrorType = void 0;
/**
 * Authentication error types
 */
var AuthErrorType;
(function (AuthErrorType) {
    AuthErrorType["INVALID_TOKEN"] = "INVALID_TOKEN";
    AuthErrorType["EXPIRED_TOKEN"] = "EXPIRED_TOKEN";
    AuthErrorType["INVALID_SIGNATURE"] = "INVALID_SIGNATURE";
    AuthErrorType["INVALID_ISSUER"] = "INVALID_ISSUER";
    AuthErrorType["INVALID_AUDIENCE"] = "INVALID_AUDIENCE";
    AuthErrorType["MISSING_TOKEN"] = "MISSING_TOKEN";
    AuthErrorType["JWKS_FETCH_FAILED"] = "JWKS_FETCH_FAILED";
    AuthErrorType["RATE_LIMIT_EXCEEDED"] = "RATE_LIMIT_EXCEEDED";
    AuthErrorType["AUTHORIZATION_FAILED"] = "AUTHORIZATION_FAILED";
    AuthErrorType["CONFIGURATION_ERROR"] = "CONFIGURATION_ERROR";
})(AuthErrorType || (exports.AuthErrorType = AuthErrorType = {}));
/**
 * Custom authentication error class
 */
class AuthenticationError extends Error {
    constructor(type, message, statusCode = 401, details) {
        super(message);
        this.type = type;
        this.statusCode = statusCode;
        this.details = details;
        this.name = 'AuthenticationError';
    }
}
exports.AuthenticationError = AuthenticationError;
