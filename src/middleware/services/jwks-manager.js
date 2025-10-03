"use strict";
/**
 * JWKS Manager for Backstage JWT Authentication
 *
 * Manages JSON Web Key Set (JWKS) fetching, caching, and auto-refresh.
 * Implements retry logic with exponential backoff for resilient operation.
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWKSManager = void 0;
const node_fetch_1 = __importDefault(require("node-fetch"));
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
const backstage_auth_1 = require("../types/backstage-auth");
/**
 * JWKS Manager class
 * Handles fetching and caching of JWKS from Backstage
 */
class JWKSManager {
    constructor(config) {
        this.client = null;
        this.cache = null;
        this.fetchPromise = null;
        this.config = config;
        this.initializeClient();
    }
    /**
     * Initialize JWKS client with configuration
     */
    initializeClient() {
        const jwksUri = this.buildJwksUri();
        this.client = (0, jwks_rsa_1.default)({
            jwksUri,
            cache: true,
            cacheMaxAge: this.config.jwksCacheTTL || 3600000, // 1 hour default
            rateLimit: true,
            jwksRequestsPerMinute: 10,
        });
        console.log(`[JWKS Manager] Initialized with URI: ${jwksUri}`);
    }
    /**
     * Build full JWKS URI from config
     */
    buildJwksUri() {
        const baseUrl = this.config.backstageUrl.replace(/\/$/, '');
        const jwksPath = this.config.jwksPath || '/api/auth/.well-known/jwks.json';
        return `${baseUrl}${jwksPath}`;
    }
    /**
     * Get signing key for JWT verification
     * @param kid - Key ID from JWT header
     * @returns Public key for verification
     */
    getSigningKey(kid) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.client) {
                throw new backstage_auth_1.AuthenticationError('CONFIGURATION_ERROR', 'JWKS client not initialized', 500);
            }
            try {
                // Check if cache needs refresh
                yield this.ensureCacheValid();
                // Get key from jwks-rsa client
                const key = yield this.client.getSigningKey(kid);
                const publicKey = key.getPublicKey();
                console.log(`[JWKS Manager] Retrieved signing key for kid: ${kid}`);
                return publicKey;
            }
            catch (error) {
                console.error(`[JWKS Manager] Failed to get signing key:`, error);
                throw new backstage_auth_1.AuthenticationError('JWKS_FETCH_FAILED', 'Failed to retrieve signing key', 500, { kid, error: error instanceof Error ? error.message : String(error) });
            }
        });
    }
    /**
     * Ensure JWKS cache is valid, refresh if needed
     */
    ensureCacheValid() {
        return __awaiter(this, void 0, void 0, function* () {
            // If already fetching, wait for that operation
            if (this.fetchPromise) {
                return this.fetchPromise;
            }
            const now = Date.now();
            const cacheTTL = this.config.jwksCacheTTL || 3600000;
            // Check if cache exists and is still valid
            if (this.cache && now < this.cache.expiresAt) {
                return;
            }
            // Fetch new JWKS with retry logic
            this.fetchPromise = this.fetchJWKSWithRetry();
            try {
                yield this.fetchPromise;
            }
            finally {
                this.fetchPromise = null;
            }
        });
    }
    /**
     * Fetch JWKS with exponential backoff retry logic
     */
    fetchJWKSWithRetry() {
        return __awaiter(this, void 0, void 0, function* () {
            const maxAttempts = this.config.maxRetryAttempts || 3;
            let lastError = null;
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    yield this.fetchJWKS();
                    console.log(`[JWKS Manager] Successfully fetched JWKS on attempt ${attempt}`);
                    return;
                }
                catch (error) {
                    lastError = error instanceof Error ? error : new Error(String(error));
                    console.error(`[JWKS Manager] Fetch attempt ${attempt} failed:`, lastError.message);
                    if (attempt < maxAttempts) {
                        // Exponential backoff: 1s, 2s, 4s...
                        const delayMs = Math.pow(2, attempt - 1) * 1000;
                        console.log(`[JWKS Manager] Retrying in ${delayMs}ms...`);
                        yield this.delay(delayMs);
                    }
                }
            }
            throw new backstage_auth_1.AuthenticationError('JWKS_FETCH_FAILED', `Failed to fetch JWKS after ${maxAttempts} attempts`, 500, { lastError: lastError === null || lastError === void 0 ? void 0 : lastError.message });
        });
    }
    /**
     * Fetch JWKS from Backstage
     */
    fetchJWKS() {
        return __awaiter(this, void 0, void 0, function* () {
            const jwksUri = this.buildJwksUri();
            console.log(`[JWKS Manager] Fetching JWKS from ${jwksUri}`);
            const response = yield (0, node_fetch_1.default)(jwksUri, {
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'claude-flow-ui/1.0',
                },
                timeout: 10000, // 10 second timeout
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const jwks = yield response.json();
            if (!jwks || !Array.isArray(jwks.keys)) {
                throw new Error('Invalid JWKS format: missing keys array');
            }
            const now = Date.now();
            const ttl = this.config.jwksCacheTTL || 3600000;
            this.cache = {
                keys: jwks.keys,
                cachedAt: now,
                expiresAt: now + ttl,
            };
            console.log(`[JWKS Manager] Cached ${jwks.keys.length} keys, expires at ${new Date(this.cache.expiresAt).toISOString()}`);
        });
    }
    /**
     * Force refresh of JWKS cache
     */
    refresh() {
        return __awaiter(this, void 0, void 0, function* () {
            console.log('[JWKS Manager] Forcing cache refresh');
            this.cache = null;
            yield this.ensureCacheValid();
        });
    }
    /**
     * Get cache statistics
     */
    getCacheStats() {
        var _a, _b;
        return {
            cached: this.cache !== null,
            expiresAt: ((_a = this.cache) === null || _a === void 0 ? void 0 : _a.expiresAt) || null,
            keysCount: ((_b = this.cache) === null || _b === void 0 ? void 0 : _b.keys.length) || 0,
        };
    }
    /**
     * Delay helper for retry logic
     */
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    /**
     * Cleanup resources
     */
    destroy() {
        this.client = null;
        this.cache = null;
        this.fetchPromise = null;
        console.log('[JWKS Manager] Destroyed');
    }
}
exports.JWKSManager = JWKSManager;
