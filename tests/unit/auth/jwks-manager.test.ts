/**
 * JWKS Manager Unit Tests
 *
 * Tests for JWKS (JSON Web Key Set) fetching, caching, and key rotation.
 * Validates the security and performance of public key management.
 */

import { JWKSManager } from '@/services/jwks-manager';
import fetch from 'node-fetch';

// Mock fetch
jest.mock('node-fetch');
const mockFetch = fetch as jest.MockedFunction<typeof fetch>;

describe('JWKSManager', () => {
  let jwksManager: JWKSManager;
  const mockBackstageUrl = 'https://backstage.example.com';
  const mockJWKSPath = '/api/.well-known/jwks.json';

  const mockJWKS = {
    keys: [
      {
        kid: 'key-1',
        kty: 'RSA',
        use: 'sig',
        n: 'xjlCRBqkQGqkHyh6pWvZDXOYiMYfpEQgj45r0JJp3vpjUkwFMZbV9kq5_vFr-zZ7p...',
        e: 'AQAB',
      },
      {
        kid: 'key-2',
        kty: 'RSA',
        use: 'sig',
        n: 'yUjBkPqQJKBhHGJp8wVWDeXNJiYFhQRHj3p1VkJIq4XJQukLKzq6aW6pFr_aW8r...',
        e: 'AQAB',
      },
    ],
  };

  beforeEach(() => {
    jwksManager = new JWKSManager({
      backstageUrl: mockBackstageUrl,
      jwksPath: mockJWKSPath,
      cacheTTL: 3600,
      maxKeys: 10,
    });

    mockFetch.mockClear();
  });

  describe('JWKS Fetching', () => {
    test('should fetch JWKS from Backstage endpoint', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      const keys = await jwksManager.fetchJWKS();

      expect(mockFetch).toHaveBeenCalledWith(
        `${mockBackstageUrl}${mockJWKSPath}`,
        expect.objectContaining({
          timeout: expect.any(Number),
        })
      );
      expect(keys).toEqual(mockJWKS.keys);
    });

    test('should throw error on failed JWKS fetch', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        statusText: 'Not Found',
      } as any);

      await expect(jwksManager.fetchJWKS()).rejects.toThrow(
        'JWKS fetch failed: Not Found'
      );
    });

    test('should retry JWKS fetch with exponential backoff', async () => {
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockJWKS,
        } as any);

      const keys = await jwksManager.fetchJWKS();

      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(keys).toEqual(mockJWKS.keys);
    });

    test('should timeout after maximum retry attempts', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      await expect(jwksManager.fetchJWKS()).rejects.toThrow(
        /JWKS fetch failed after \d+ attempts/
      );

      expect(mockFetch).toHaveBeenCalledTimes(3); // Default retry attempts
    });

    test('should validate JWKS response format', async () => {
      const invalidJWKS = { invalid: 'format' };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => invalidJWKS,
      } as any);

      await expect(jwksManager.fetchJWKS()).rejects.toThrow(
        'Invalid JWKS format: missing keys array'
      );
    });
  });

  describe('JWKS Caching', () => {
    test('should cache JWKS keys after first fetch', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      // First fetch
      const keys1 = await jwksManager.getPublicKey('key-1');

      // Second fetch (should use cache)
      const keys2 = await jwksManager.getPublicKey('key-1');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(keys1).toEqual(keys2);
    });

    test('should refresh cache after TTL expires', async () => {
      const shortTTLManager = new JWKSManager({
        backstageUrl: mockBackstageUrl,
        jwksPath: mockJWKSPath,
        cacheTTL: 1, // 1 second
        maxKeys: 10,
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      // First fetch
      await shortTTLManager.getPublicKey('key-1');

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Second fetch (should fetch again)
      await shortTTLManager.getPublicKey('key-1');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    test('should use expired cache as fallback on fetch failure', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockJWKS,
        } as any)
        .mockRejectedValueOnce(new Error('Service unavailable'));

      // First fetch (successful)
      const key1 = await jwksManager.getPublicKey('key-1');

      // Manually expire cache
      (jwksManager as any).cacheExpiry = new Date(Date.now() - 1000);

      // Second fetch (fails, should use expired cache)
      const key2 = await jwksManager.getPublicKey('key-1');

      expect(key1).toEqual(key2);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    test('should respect maximum cache size', async () => {
      const smallCacheManager = new JWKSManager({
        backstageUrl: mockBackstageUrl,
        jwksPath: mockJWKSPath,
        cacheTTL: 3600,
        maxKeys: 2, // Only cache 2 keys
      });

      const manyKeys = {
        keys: Array.from({ length: 5 }, (_, i) => ({
          kid: `key-${i}`,
          kty: 'RSA',
          use: 'sig',
          n: 'test',
          e: 'AQAB',
        })),
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => manyKeys,
      } as any);

      await smallCacheManager.getPublicKey('key-0');

      const cacheSize = (smallCacheManager as any).cache.size;
      expect(cacheSize).toBeLessThanOrEqual(2);
    });

    test('should implement LRU eviction strategy', async () => {
      const lruManager = new JWKSManager({
        backstageUrl: mockBackstageUrl,
        jwksPath: mockJWKSPath,
        cacheTTL: 3600,
        maxKeys: 2,
      });

      const keys = {
        keys: [
          { kid: 'key-1', kty: 'RSA', use: 'sig', n: 'test', e: 'AQAB' },
          { kid: 'key-2', kty: 'RSA', use: 'sig', n: 'test', e: 'AQAB' },
          { kid: 'key-3', kty: 'RSA', use: 'sig', n: 'test', e: 'AQAB' },
        ],
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => keys,
      } as any);

      // Access keys in order
      await lruManager.getPublicKey('key-1');
      await lruManager.getPublicKey('key-2');

      // Access key-3 (should evict key-1)
      await lruManager.getPublicKey('key-3');

      // Verify key-1 was evicted
      const cache = (lruManager as any).cache;
      expect(cache.has('key-1')).toBe(false);
      expect(cache.has('key-2')).toBe(true);
      expect(cache.has('key-3')).toBe(true);
    });
  });

  describe('Key Rotation Handling', () => {
    test('should handle JWKS key rotation', async () => {
      const initialKeys = {
        keys: [
          { kid: 'old-key', kty: 'RSA', use: 'sig', n: 'old', e: 'AQAB' },
        ],
      };

      const rotatedKeys = {
        keys: [
          { kid: 'old-key', kty: 'RSA', use: 'sig', n: 'old', e: 'AQAB' },
          { kid: 'new-key', kty: 'RSA', use: 'sig', n: 'new', e: 'AQAB' },
        ],
      };

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialKeys,
        } as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => rotatedKeys,
        } as any);

      // Get old key
      await jwksManager.getPublicKey('old-key');

      // Force refresh
      await jwksManager.refreshKeys();

      // New key should now be available
      const newKey = await jwksManager.getPublicKey('new-key');
      expect(newKey).toBeDefined();
    });

    test('should refresh keys before expiry for smooth rotation', async () => {
      const refreshManager = new JWKSManager({
        backstageUrl: mockBackstageUrl,
        jwksPath: mockJWKSPath,
        cacheTTL: 3600,
        maxKeys: 10,
        refreshBeforeExpiry: 300, // Refresh 5 minutes before expiry
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      await refreshManager.getPublicKey('key-1');

      // Simulate time near expiry
      (refreshManager as any).cacheExpiry = new Date(Date.now() + 200000); // 200s remaining

      // Should trigger proactive refresh
      await refreshManager.getPublicKey('key-1');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    test('should handle missing key ID gracefully', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      await expect(jwksManager.getPublicKey('non-existent-key')).rejects.toThrow(
        'Public key not found for kid: non-existent-key'
      );
    });

    test('should retry fetch when requested key is missing', async () => {
      const initialKeys = {
        keys: [
          { kid: 'key-1', kty: 'RSA', use: 'sig', n: 'test', e: 'AQAB' },
        ],
      };

      const updatedKeys = {
        keys: [
          { kid: 'key-1', kty: 'RSA', use: 'sig', n: 'test', e: 'AQAB' },
          { kid: 'key-2', kty: 'RSA', use: 'sig', n: 'test', e: 'AQAB' },
        ],
      };

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => initialKeys,
        } as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => updatedKeys,
        } as any);

      // Fetch key-2 (not in initial cache)
      const key2 = await jwksManager.getPublicKey('key-2');

      expect(key2).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Performance and Concurrency', () => {
    test('should handle concurrent key requests efficiently', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      // Make 10 concurrent requests for the same key
      const promises = Array.from({ length: 10 }, () =>
        jwksManager.getPublicKey('key-1')
      );

      await Promise.all(promises);

      // Should only fetch once despite concurrent requests
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    test('should cache JWKS fetch promise to prevent duplicate requests', async () => {
      let fetchCount = 0;
      mockFetch.mockImplementation(async () => {
        fetchCount++;
        await new Promise(resolve => setTimeout(resolve, 100));
        return {
          ok: true,
          json: async () => mockJWKS,
        } as any;
      });

      // Start multiple concurrent fetches
      const promises = [
        jwksManager.getPublicKey('key-1'),
        jwksManager.getPublicKey('key-2'),
        jwksManager.getPublicKey('key-1'),
      ];

      await Promise.all(promises);

      // Should only make one fetch request
      expect(fetchCount).toBe(1);
    });

    test('should measure and log cache hit rate', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      // First fetch (cache miss)
      await jwksManager.getPublicKey('key-1');

      // Subsequent fetches (cache hits)
      await jwksManager.getPublicKey('key-1');
      await jwksManager.getPublicKey('key-1');
      await jwksManager.getPublicKey('key-1');

      const metrics = jwksManager.getCacheMetrics();

      expect(metrics.hits).toBe(3);
      expect(metrics.misses).toBe(1);
      expect(metrics.hitRate).toBeCloseTo(0.75);
    });
  });

  describe('Security', () => {
    test('should validate HTTPS endpoint in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      expect(() => {
        new JWKSManager({
          backstageUrl: 'http://insecure.example.com',
          jwksPath: mockJWKSPath,
          cacheTTL: 3600,
          maxKeys: 10,
        });
      }).toThrow('HTTPS required in production');

      process.env.NODE_ENV = originalEnv;
    });

    test('should sanitize JWKS path to prevent path traversal', () => {
      expect(() => {
        new JWKSManager({
          backstageUrl: mockBackstageUrl,
          jwksPath: '/../../../etc/passwd',
          cacheTTL: 3600,
          maxKeys: 10,
        });
      }).toThrow('Invalid JWKS path');
    });

    test('should validate key format before caching', async () => {
      const invalidKey = {
        keys: [
          { kid: 'key-1', invalid: 'format' }, // Missing required fields
        ],
      };

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => invalidKey,
      } as any);

      await expect(jwksManager.getPublicKey('key-1')).rejects.toThrow(
        'Invalid key format'
      );
    });

    test('should not log sensitive key material', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => mockJWKS,
      } as any);

      await jwksManager.getPublicKey('key-1');

      const allLogs = consoleSpy.mock.calls.flat().join(' ');

      // Should not contain full key material
      expect(allLogs).not.toContain(mockJWKS.keys[0].n);

      consoleSpy.mockRestore();
    });
  });

  describe('Error Recovery', () => {
    test('should clear cache on persistent fetch errors', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockJWKS,
        } as any)
        .mockRejectedValue(new Error('Persistent error'));

      // Initial successful fetch
      await jwksManager.getPublicKey('key-1');

      // Expire cache
      (jwksManager as any).cacheExpiry = new Date(Date.now() - 1000);

      // Multiple failed fetches
      await expect(jwksManager.getPublicKey('key-1')).rejects.toThrow();

      // Cache should be cleared for fresh start
      const cacheSize = (jwksManager as any).cache.size;
      expect(cacheSize).toBe(0);
    });

    test('should emit events on fetch failure for monitoring', async () => {
      const errorHandler = jest.fn();
      jwksManager.on('fetch-error', errorHandler);

      mockFetch.mockRejectedValue(new Error('Fetch failed'));

      await expect(jwksManager.fetchJWKS()).rejects.toThrow();

      expect(errorHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(Error),
          retries: expect.any(Number),
        })
      );
    });
  });
});
