/**
 * JWKS Manager for Backstage JWT Authentication
 *
 * Manages JSON Web Key Set (JWKS) fetching, caching, and auto-refresh.
 * Implements retry logic with exponential backoff for resilient operation.
 */

import fetch from 'node-fetch';
import jwksClient from 'jwks-rsa';
import type { BackstageAuthConfig, JWKSCacheEntry, AuthErrorType } from '../types/backstage-auth';
import { AuthenticationError } from '../types/backstage-auth';

/**
 * JWKS Manager class
 * Handles fetching and caching of JWKS from Backstage
 */
export class JWKSManager {
  private client: jwksClient.JwksClient | null = null;
  private cache: JWKSCacheEntry | null = null;
  private config: BackstageAuthConfig;
  private fetchPromise: Promise<void> | null = null;

  constructor(config: BackstageAuthConfig) {
    this.config = config;
    this.initializeClient();
  }

  /**
   * Initialize JWKS client with configuration
   */
  private initializeClient(): void {
    const jwksUri = this.buildJwksUri();

    this.client = jwksClient({
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
  private buildJwksUri(): string {
    const baseUrl = this.config.backstageUrl.replace(/\/$/, '');
    const jwksPath = this.config.jwksPath || '/api/auth/.well-known/jwks.json';
    return `${baseUrl}${jwksPath}`;
  }

  /**
   * Get signing key for JWT verification
   * @param kid - Key ID from JWT header
   * @returns Public key for verification
   */
  async getSigningKey(kid: string): Promise<string> {
    if (!this.client) {
      throw new AuthenticationError(
        'CONFIGURATION_ERROR' as AuthErrorType,
        'JWKS client not initialized',
        500
      );
    }

    try {
      // Check if cache needs refresh
      await this.ensureCacheValid();

      // Get key from jwks-rsa client
      const key = await this.client.getSigningKey(kid);
      const publicKey = key.getPublicKey();

      console.log(`[JWKS Manager] Retrieved signing key for kid: ${kid}`);
      return publicKey;
    } catch (error) {
      console.error(`[JWKS Manager] Failed to get signing key:`, error);
      throw new AuthenticationError(
        'JWKS_FETCH_FAILED' as AuthErrorType,
        'Failed to retrieve signing key',
        500,
        { kid, error: error instanceof Error ? error.message : String(error) }
      );
    }
  }

  /**
   * Ensure JWKS cache is valid, refresh if needed
   */
  private async ensureCacheValid(): Promise<void> {
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
      await this.fetchPromise;
    } finally {
      this.fetchPromise = null;
    }
  }

  /**
   * Fetch JWKS with exponential backoff retry logic
   */
  private async fetchJWKSWithRetry(): Promise<void> {
    const maxAttempts = this.config.maxRetryAttempts || 3;
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await this.fetchJWKS();
        console.log(`[JWKS Manager] Successfully fetched JWKS on attempt ${attempt}`);
        return;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        console.error(`[JWKS Manager] Fetch attempt ${attempt} failed:`, lastError.message);

        if (attempt < maxAttempts) {
          // Exponential backoff: 1s, 2s, 4s...
          const delayMs = Math.pow(2, attempt - 1) * 1000;
          console.log(`[JWKS Manager] Retrying in ${delayMs}ms...`);
          await this.delay(delayMs);
        }
      }
    }

    throw new AuthenticationError(
      'JWKS_FETCH_FAILED' as AuthErrorType,
      `Failed to fetch JWKS after ${maxAttempts} attempts`,
      500,
      { lastError: lastError?.message }
    );
  }

  /**
   * Fetch JWKS from Backstage
   */
  private async fetchJWKS(): Promise<void> {
    const jwksUri = this.buildJwksUri();

    console.log(`[JWKS Manager] Fetching JWKS from ${jwksUri}`);

    const response = await fetch(jwksUri, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'claude-flow-ui/1.0',
      },
      timeout: 10000, // 10 second timeout
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const jwks = await response.json();

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
  }

  /**
   * Force refresh of JWKS cache
   */
  async refresh(): Promise<void> {
    console.log('[JWKS Manager] Forcing cache refresh');
    this.cache = null;
    await this.ensureCacheValid();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { cached: boolean; expiresAt: number | null; keysCount: number } {
    return {
      cached: this.cache !== null,
      expiresAt: this.cache?.expiresAt || null,
      keysCount: this.cache?.keys.length || 0,
    };
  }

  /**
   * Delay helper for retry logic
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    this.client = null;
    this.cache = null;
    this.fetchPromise = null;
    console.log('[JWKS Manager] Destroyed');
  }
}
