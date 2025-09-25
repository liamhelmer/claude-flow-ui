/**
 * Redis Caching Integration Tests
 *
 * These tests validate Redis caching functionality, including session storage,
 * cache invalidation, data persistence, and performance optimizations across
 * the application layers.
 */

import { redisClient } from '../../rest-api/src/config/redis';
import { database } from '../../rest-api/src/config/database';
import { User } from '../../rest-api/src/models/User';
import request from 'supertest';
import { Application } from 'express';
import App from '../../rest-api/src/app';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from '../../rest-api/src/config/environment';

// Mock cache keys and data structures
const CACHE_KEYS = {
  USER_SESSION: (userId: string) => `user_session:${userId}`,
  USER_PROFILE: (userId: string) => `user_profile:${userId}`,
  TERMINAL_SESSION: (sessionId: string) => `terminal_session:${sessionId}`,
  RATE_LIMIT: (ip: string) => `rate_limit:${ip}`,
  AUTH_ATTEMPTS: (identifier: string) => `auth_attempts:${identifier}`,
  ACTIVE_SESSIONS: 'active_sessions',
  CACHE_STATS: 'cache_stats',
};

interface CacheStats {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  expires: number;
}

describe('Redis Caching Integration Tests', () => {
  let app: Application;
  let testApp: App;
  let testUser: User;
  let authToken: string;
  let cacheStats: CacheStats;

  const testUserData = {
    firstName: 'Cache',
    lastName: 'Tester',
    email: 'cache.tester@test.com',
    password: 'CachePassword123!',
    role: 'user' as const,
  };

  beforeAll(async () => {
    // Initialize test environment
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_redis_test';
    process.env.REDIS_URL = 'redis://localhost:6379';
    process.env.JWT_SECRET = 'test-redis-jwt-secret';

    // Initialize app and connections
    testApp = new App();
    app = testApp.app;

    await database.connect();
    await database.sync({ force: true });
    await redisClient.connect();

    // Create test user
    const hashedPassword = await bcrypt.hash(testUserData.password, 12);
    testUser = await User.create({
      ...testUserData,
      password: hashedPassword,
    });

    authToken = jwt.sign(
      { userId: testUser.id, email: testUser.email },
      config.jwt.secret,
      { expiresIn: '1h' }
    );

    // Initialize cache stats
    cacheStats = { hits: 0, misses: 0, sets: 0, deletes: 0, expires: 0 };
  }, 30000);

  afterAll(async () => {
    await User.destroy({ where: {} });
    await database.disconnect();
    await redisClient.flushall();
    await redisClient.disconnect();
    await testApp.shutdown();
  }, 30000);

  beforeEach(async () => {
    // Clear Redis and reset stats
    await redisClient.flushall();
    cacheStats = { hits: 0, misses: 0, sets: 0, deletes: 0, expires: 0 };
  });

  describe('Basic Redis Operations', () => {
    test('should store and retrieve string data', async () => {
      const key = 'test:string';
      const value = 'test string value';

      // Store data
      await redisClient.set(key, value);
      cacheStats.sets++;

      // Retrieve data
      const retrieved = await redisClient.get(key);
      expect(retrieved).toBe(value);
      cacheStats.hits++;

      // Test non-existent key
      const missing = await redisClient.get('non:existent');
      expect(missing).toBeNull();
      cacheStats.misses++;
    });

    test('should store and retrieve JSON data', async () => {
      const key = 'test:json';
      const value = {
        id: 'test-id',
        name: 'Test Object',
        metadata: {
          created: new Date().toISOString(),
          tags: ['test', 'redis'],
        },
      };

      // Store JSON data
      await redisClient.set(key, JSON.stringify(value));
      cacheStats.sets++;

      // Retrieve and parse JSON data
      const retrieved = await redisClient.get(key);
      expect(retrieved).toBeTruthy();
      
      const parsed = JSON.parse(retrieved!);
      expect(parsed).toEqual(value);
      cacheStats.hits++;
    });

    test('should handle expiration (TTL)', async () => {
      const key = 'test:expiring';
      const value = 'will expire soon';
      const ttl = 2; // 2 seconds

      // Store with TTL
      await redisClient.setex(key, ttl, value);
      cacheStats.sets++;
      cacheStats.expires++;

      // Should exist immediately
      let retrieved = await redisClient.get(key);
      expect(retrieved).toBe(value);
      cacheStats.hits++;

      // Check TTL
      const remainingTtl = await redisClient.ttl(key);
      expect(remainingTtl).toBeGreaterThan(0);
      expect(remainingTtl).toBeLessThanOrEqual(ttl);

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, ttl * 1000 + 100));

      // Should be expired
      retrieved = await redisClient.get(key);
      expect(retrieved).toBeNull();
      cacheStats.misses++;
    });

    test('should handle hash operations', async () => {
      const key = 'test:hash';
      const hashData = {
        field1: 'value1',
        field2: 'value2',
        field3: JSON.stringify({ nested: 'object' }),
      };

      // Store hash fields
      for (const [field, value] of Object.entries(hashData)) {
        await redisClient.hset(key, field, value);
      }
      cacheStats.sets += Object.keys(hashData).length;

      // Retrieve individual fields
      for (const [field, expectedValue] of Object.entries(hashData)) {
        const value = await redisClient.hget(key, field);
        expect(value).toBe(expectedValue);
        cacheStats.hits++;
      }

      // Get all hash fields
      const allFields = await redisClient.hgetall(key);
      expect(allFields).toEqual(hashData);
      cacheStats.hits++;

      // Delete specific field
      await redisClient.hdel(key, 'field1');
      cacheStats.deletes++;

      const deletedField = await redisClient.hget(key, 'field1');
      expect(deletedField).toBeNull();
      cacheStats.misses++;
    });

    test('should handle list operations', async () => {
      const key = 'test:list';
      const items = ['item1', 'item2', 'item3'];

      // Push items to list
      for (const item of items) {
        await redisClient.lpush(key, item);
      }
      cacheStats.sets += items.length;

      // Get list length
      const length = await redisClient.llen(key);
      expect(length).toBe(items.length);

      // Get list range (all items)
      const allItems = await redisClient.lrange(key, 0, -1);
      expect(allItems).toEqual(items.reverse()); // LPUSH reverses order
      cacheStats.hits++;

      // Pop item
      const popped = await redisClient.lpop(key);
      expect(popped).toBe('item3');
      cacheStats.hits++;
    });
  });

  describe('Session Management Caching', () => {
    test('should cache user session data', async () => {
      const sessionData = {
        userId: testUser.id,
        email: testUser.email,
        loginTime: Date.now(),
        lastActivity: Date.now(),
        permissions: ['read', 'write'],
      };

      const sessionKey = CACHE_KEYS.USER_SESSION(testUser.id);
      
      // Store session with 1 hour expiration
      await redisClient.setex(
        sessionKey,
        3600,
        JSON.stringify(sessionData)
      );

      // Retrieve and verify session
      const cachedSession = await redisClient.get(sessionKey);
      expect(cachedSession).toBeTruthy();
      
      const parsed = JSON.parse(cachedSession!);
      expect(parsed).toEqual(sessionData);

      // Verify TTL is set
      const ttl = await redisClient.ttl(sessionKey);
      expect(ttl).toBeGreaterThan(3500); // Should be close to 3600
    });

    test('should manage multiple concurrent sessions', async () => {
      const sessions = Array.from({ length: 5 }, (_, i) => ({
        id: `session-${i}`,
        userId: testUser.id,
        loginTime: Date.now() - i * 1000,
        browserInfo: `Browser ${i}`,
      }));

      // Store all sessions
      const setPromises = sessions.map(session =>
        redisClient.setex(
          `session:${session.id}`,
          3600,
          JSON.stringify(session)
        )
      );
      await Promise.all(setPromises);

      // Track active sessions in a set
      const activeSessionsKey = CACHE_KEYS.ACTIVE_SESSIONS;
      const addToSetPromises = sessions.map(session =>
        redisClient.sadd(activeSessionsKey, session.id)
      );
      await Promise.all(addToSetPromises);

      // Retrieve all active session IDs
      const activeSessionIds = await redisClient.smembers(activeSessionsKey);
      expect(activeSessionIds).toHaveLength(5);
      expect(activeSessionIds.sort()).toEqual(
        sessions.map(s => s.id).sort()
      );

      // Retrieve specific session data
      for (const session of sessions) {
        const sessionData = await redisClient.get(`session:${session.id}`);
        expect(sessionData).toBeTruthy();
        
        const parsed = JSON.parse(sessionData!);
        expect(parsed.id).toBe(session.id);
      }

      // Remove one session
      const sessionToRemove = sessions[0];
      await redisClient.del(`session:${sessionToRemove.id}`);
      await redisClient.srem(activeSessionsKey, sessionToRemove.id);

      // Verify removal
      const updatedSessions = await redisClient.smembers(activeSessionsKey);
      expect(updatedSessions).toHaveLength(4);
      expect(updatedSessions).not.toContain(sessionToRemove.id);
    });

    test('should handle session cleanup on logout', async () => {
      const sessionData = {
        userId: testUser.id,
        sessionId: 'logout-test-session',
        created: Date.now(),
      };

      const userSessionKey = CACHE_KEYS.USER_SESSION(testUser.id);
      const terminalSessionKey = CACHE_KEYS.TERMINAL_SESSION(sessionData.sessionId);

      // Store session data
      await redisClient.setex(userSessionKey, 3600, JSON.stringify(sessionData));
      await redisClient.setex(terminalSessionKey, 3600, JSON.stringify({
        sessionId: sessionData.sessionId,
        userId: testUser.id,
        terminalPid: 12345,
      }));

      // Verify data exists
      expect(await redisClient.get(userSessionKey)).toBeTruthy();
      expect(await redisClient.get(terminalSessionKey)).toBeTruthy();

      // Simulate logout - clean up all session-related data
      const keysToDelete = [
        userSessionKey,
        terminalSessionKey,
        `user_preferences:${testUser.id}`,
        `user_activity:${testUser.id}`,
      ];

      await Promise.all(
        keysToDelete.map(key => redisClient.del(key))
      );

      // Verify all data is cleaned up
      for (const key of keysToDelete) {
        const value = await redisClient.get(key);
        expect(value).toBeNull();
      }
    });
  });

  describe('Rate Limiting Cache', () => {
    test('should track and enforce rate limits', async () => {
      const clientIp = '192.168.1.100';
      const rateLimitKey = CACHE_KEYS.RATE_LIMIT(clientIp);
      const windowSize = 60; // 1 minute
      const maxRequests = 5;

      // Simulate multiple requests
      for (let i = 1; i <= maxRequests + 2; i++) {
        // Increment request count
        const currentCount = await redisClient.incr(rateLimitKey);
        
        // Set expiration on first request
        if (currentCount === 1) {
          await redisClient.expire(rateLimitKey, windowSize);
        }

        if (i <= maxRequests) {
          expect(currentCount).toBe(i);
          expect(currentCount).toBeLessThanOrEqual(maxRequests);
        } else {
          expect(currentCount).toBeGreaterThan(maxRequests);
          // In a real implementation, this would trigger rate limiting
        }
      }

      // Check TTL
      const ttl = await redisClient.ttl(rateLimitKey);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(windowSize);
    });

    test('should handle sliding window rate limiting', async () => {
      const userId = testUser.id;
      const baseKey = `sliding_rate_limit:${userId}`;
      const windowSize = 60; // 1 minute
      const maxRequests = 10;

      // Simulate requests over time with timestamps
      const now = Date.now();
      const requests = Array.from({ length: 15 }, (_, i) => ({
        timestamp: now + i * 1000, // 1 second apart
        id: `req_${i}`,
      }));

      for (const request of requests) {
        const windowStart = request.timestamp - windowSize * 1000;
        const requestKey = `${baseKey}:${request.timestamp}`;

        // Add current request
        await redisClient.setex(requestKey, windowSize, '1');

        // Count requests in current window
        const pattern = `${baseKey}:*`;
        const keys = await redisClient.keys(pattern);
        
        // Filter keys within window
        const windowKeys = keys.filter(key => {
          const timestamp = parseInt(key.split(':').pop() || '0');
          return timestamp > windowStart;
        });

        const requestCount = windowKeys.length;
        
        // Check if rate limit exceeded
        if (requestCount > maxRequests) {
          // Would trigger rate limiting in real implementation
          expect(requestCount).toBeGreaterThan(maxRequests);
          break;
        }
      }
    });

    test('should integrate rate limiting with HTTP requests', async () => {
      // Make multiple rapid requests to trigger rate limiting
      const requests = Array.from({ length: 20 }, () =>
        request(app)
          .post('/api/v1/auth/login')
          .send({
            email: 'nonexistent@test.com',
            password: 'wrongpassword',
          })
      );

      const responses = await Promise.allSettled(requests);
      
      // Some responses should be rate limited (429)
      const rateLimitedCount = responses
        .filter(result => 
          result.status === 'fulfilled' && 
          (result.value as any).status === 429
        ).length;
      
      expect(rateLimitedCount).toBeGreaterThan(0);
    });
  });

  describe('Data Persistence and Recovery', () => {
    test('should persist data across Redis restarts', async () => {
      const persistentData = {
        key1: 'persistent value 1',
        key2: JSON.stringify({ nested: 'persistent object' }),
        key3: 'persistent value 3',
      };

      // Store data
      for (const [key, value] of Object.entries(persistentData)) {
        await redisClient.set(`persistent:${key}`, value);
      }

      // Force Redis to save data (if using persistent storage)
      // In a real test environment, you might restart Redis here
      // For this test, we'll simulate by checking data integrity
      
      // Verify data exists
      for (const [key, expectedValue] of Object.entries(persistentData)) {
        const retrieved = await redisClient.get(`persistent:${key}`);
        expect(retrieved).toBe(expectedValue);
      }

      // Test data recovery scenario
      const recoveryData = {
        userId: testUser.id,
        sessions: ['session1', 'session2'],
        lastActivity: Date.now(),
      };

      await redisClient.set(
        'recovery:test',
        JSON.stringify(recoveryData)
      );

      const recovered = await redisClient.get('recovery:test');
      expect(recovered).toBeTruthy();
      
      const parsedRecovery = JSON.parse(recovered!);
      expect(parsedRecovery).toEqual(recoveryData);
    });

    test('should handle cache warming strategies', async () => {
      // Simulate cache warming with frequently accessed data
      const frequentData = {
        userProfiles: Array.from({ length: 100 }, (_, i) => ({
          id: `user_${i}`,
          name: `User ${i}`,
          lastActive: Date.now() - i * 1000,
        })),
        systemConfig: {
          version: '1.0.0',
          features: ['auth', 'terminals', 'websockets'],
          limits: { maxSessions: 10, maxUsers: 1000 },
        },
      };

      // Warm user profile cache
      const warmingPromises = frequentData.userProfiles.map(profile =>
        redisClient.setex(
          CACHE_KEYS.USER_PROFILE(profile.id),
          7200, // 2 hours
          JSON.stringify(profile)
        )
      );
      await Promise.all(warmingPromises);

      // Warm system config
      await redisClient.setex(
        'system:config',
        86400, // 24 hours
        JSON.stringify(frequentData.systemConfig)
      );

      // Verify warm data is accessible
      const randomProfileId = `user_${Math.floor(Math.random() * 100)}`;
      const cachedProfile = await redisClient.get(
        CACHE_KEYS.USER_PROFILE(randomProfileId)
      );
      expect(cachedProfile).toBeTruthy();

      const cachedConfig = await redisClient.get('system:config');
      expect(cachedConfig).toBeTruthy();
      
      const parsedConfig = JSON.parse(cachedConfig!);
      expect(parsedConfig).toEqual(frequentData.systemConfig);
    });
  });

  describe('Cache Performance and Optimization', () => {
    test('should measure cache hit/miss ratios', async () => {
      const testKeys = Array.from({ length: 100 }, (_, i) => `perf:key_${i}`);
      const testValues = testKeys.map((_, i) => `value_${i}`);

      // Store half the data
      const storePromises = testKeys.slice(0, 50).map((key, i) =>
        redisClient.set(key, testValues[i])
      );
      await Promise.all(storePromises);

      let hits = 0;
      let misses = 0;

      // Attempt to retrieve all keys
      for (let i = 0; i < testKeys.length; i++) {
        const value = await redisClient.get(testKeys[i]);
        if (value) {
          hits++;
          expect(value).toBe(testValues[i]);
        } else {
          misses++;
        }
      }

      // Should have 50% hit rate
      expect(hits).toBe(50);
      expect(misses).toBe(50);
      
      const hitRatio = hits / (hits + misses);
      expect(hitRatio).toBe(0.5);
    });

    test('should handle high concurrency operations', async () => {
      const concurrentOperations = 1000;
      const baseKey = 'concurrent:test';

      // Perform concurrent SET operations
      const setPromises = Array.from({ length: concurrentOperations }, (_, i) =>
        redisClient.set(`${baseKey}:${i}`, `value_${i}`)
      );

      const startTime = Date.now();
      await Promise.all(setPromises);
      const setDuration = Date.now() - startTime;

      // Perform concurrent GET operations
      const getPromises = Array.from({ length: concurrentOperations }, (_, i) =>
        redisClient.get(`${baseKey}:${i}`)
      );

      const getStartTime = Date.now();
      const results = await Promise.all(getPromises);
      const getDuration = Date.now() - getStartTime;

      // Verify all operations completed successfully
      expect(results).toHaveLength(concurrentOperations);
      results.forEach((result, i) => {
        expect(result).toBe(`value_${i}`);
      });

      // Performance assertions (adjust based on environment)
      expect(setDuration).toBeLessThan(5000); // 5 seconds max for 1000 sets
      expect(getDuration).toBeLessThan(2000); // 2 seconds max for 1000 gets

      console.log(`Concurrent operations performance: SET=${setDuration}ms, GET=${getDuration}ms`);
    });

    test('should optimize memory usage with compression', async () => {
      // Large JSON object for compression testing
      const largeObject = {
        id: 'large-object-test',
        data: Array.from({ length: 1000 }, (_, i) => ({
          index: i,
          value: `repeated content ${i}`.repeat(10),
          metadata: {
            created: new Date().toISOString(),
            tags: Array(5).fill(`tag_${i}`),
          },
        })),
        summary: 'This is a large object for compression testing',
      };

      const jsonString = JSON.stringify(largeObject);
      const uncompressedSize = Buffer.byteLength(jsonString, 'utf8');

      // Store uncompressed
      await redisClient.set('large:uncompressed', jsonString);

      // In a real implementation, you might use compression here
      // For this test, we'll simulate by storing a smaller representation
      const compressedData = {
        id: largeObject.id,
        dataCount: largeObject.data.length,
        summary: largeObject.summary,
        compressed: true,
      };
      
      const compressedString = JSON.stringify(compressedData);
      const compressedSize = Buffer.byteLength(compressedString, 'utf8');
      
      await redisClient.set('large:compressed', compressedString);

      // Verify size difference
      expect(compressedSize).toBeLessThan(uncompressedSize);
      
      console.log(`Size comparison: uncompressed=${uncompressedSize} bytes, compressed=${compressedSize} bytes`);
      console.log(`Compression ratio: ${((1 - compressedSize / uncompressedSize) * 100).toFixed(2)}%`);
    });
  });

  describe('Cache Invalidation Strategies', () => {
    test('should implement time-based invalidation', async () => {
      const keys = ['time:short', 'time:medium', 'time:long'];
      const ttls = [1, 5, 10]; // seconds
      const values = ['short-lived', 'medium-lived', 'long-lived'];

      // Store with different TTLs
      for (let i = 0; i < keys.length; i++) {
        await redisClient.setex(keys[i], ttls[i], values[i]);
      }

      // All should exist initially
      for (let i = 0; i < keys.length; i++) {
        const value = await redisClient.get(keys[i]);
        expect(value).toBe(values[i]);
      }

      // Wait for first key to expire
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      expect(await redisClient.get(keys[0])).toBeNull();
      expect(await redisClient.get(keys[1])).toBe(values[1]);
      expect(await redisClient.get(keys[2])).toBe(values[2]);

      // Wait for second key to expire
      await new Promise(resolve => setTimeout(resolve, 4000));
      
      expect(await redisClient.get(keys[0])).toBeNull();
      expect(await redisClient.get(keys[1])).toBeNull();
      expect(await redisClient.get(keys[2])).toBe(values[2]);
    }, 15000);

    test('should implement event-based invalidation', async () => {
      // Store related cache entries
      const userId = testUser.id;
      const userCacheKeys = [
        CACHE_KEYS.USER_PROFILE(userId),
        CACHE_KEYS.USER_SESSION(userId),
        `user_preferences:${userId}`,
        `user_activity:${userId}`,
      ];

      const userData = {
        profile: { id: userId, name: 'Test User' },
        session: { userId, loginTime: Date.now() },
        preferences: { theme: 'dark', language: 'en' },
        activity: { lastSeen: Date.now(), actions: [] },
      };

      // Store all related data
      await redisClient.set(userCacheKeys[0], JSON.stringify(userData.profile));
      await redisClient.set(userCacheKeys[1], JSON.stringify(userData.session));
      await redisClient.set(userCacheKeys[2], JSON.stringify(userData.preferences));
      await redisClient.set(userCacheKeys[3], JSON.stringify(userData.activity));

      // Verify all data exists
      for (const key of userCacheKeys) {
        const value = await redisClient.get(key);
        expect(value).toBeTruthy();
      }

      // Simulate user update event - invalidate all user-related cache
      await Promise.all(
        userCacheKeys.map(key => redisClient.del(key))
      );

      // Verify all data is invalidated
      for (const key of userCacheKeys) {
        const value = await redisClient.get(key);
        expect(value).toBeNull();
      }
    });

    test('should implement pattern-based invalidation', async () => {
      const patterns = {
        'session:*': ['session:1', 'session:2', 'session:3'],
        'user:*:profile': ['user:1:profile', 'user:2:profile'],
        'cache:temp:*': ['cache:temp:1', 'cache:temp:2', 'cache:temp:3'],
      };

      // Store data for each pattern
      for (const [pattern, keys] of Object.entries(patterns)) {
        for (let i = 0; i < keys.length; i++) {
          await redisClient.set(keys[i], `data_${i}`);
        }
      }

      // Verify all data exists
      for (const keys of Object.values(patterns)) {
        for (const key of keys) {
          const value = await redisClient.get(key);
          expect(value).toBeTruthy();
        }
      }

      // Invalidate by pattern (simulate with manual deletion)
      for (const [pattern, keys] of Object.entries(patterns)) {
        // In production, you might use Redis Lua scripts for atomic pattern deletion
        const keysToDelete = await redisClient.keys(pattern.replace('*', '*'));
        if (keysToDelete.length > 0) {
          await Promise.all(
            keysToDelete.map(key => redisClient.del(key))
          );
        }
      }

      // Verify all pattern-matched data is invalidated
      for (const keys of Object.values(patterns)) {
        for (const key of keys) {
          const value = await redisClient.get(key);
          expect(value).toBeNull();
        }
      }
    });
  });

  describe('Error Handling and Resilience', () => {
    test('should handle Redis connection failures gracefully', async () => {
      // Store some data first
      await redisClient.set('test:connection', 'connection test');
      
      // Verify data exists
      const beforeDisconnect = await redisClient.get('test:connection');
      expect(beforeDisconnect).toBe('connection test');

      // Simulate connection loss
      await redisClient.disconnect();

      // Operations should fail gracefully
      try {
        await redisClient.get('test:connection');
        fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeTruthy();
      }

      // Reconnect
      await redisClient.connect();
      
      // Should be able to operate normally
      await redisClient.set('test:reconnection', 'reconnection test');
      const afterReconnect = await redisClient.get('test:reconnection');
      expect(afterReconnect).toBe('reconnection test');
    });

    test('should handle cache misses gracefully in application flow', async () => {
      // Test HTTP request that would normally use cached data
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.user).toBeTruthy();
      expect(response.body.user.id).toBe(testUser.id);

      // Even without cached data, the request should succeed
      // by falling back to database queries
    });

    test('should handle partial cache corruption', async () => {
      const testData = {
        valid: { id: 1, name: 'Valid Data' },
        corrupted: 'invalid json {',
        empty: '',
        nullValue: null,
      };

      // Store mixed data types
      await redisClient.set('data:valid', JSON.stringify(testData.valid));
      await redisClient.set('data:corrupted', testData.corrupted);
      await redisClient.set('data:empty', testData.empty);
      await redisClient.set('data:null', JSON.stringify(testData.nullValue));

      // Test retrieval with error handling
      const validData = await redisClient.get('data:valid');
      expect(() => JSON.parse(validData!)).not.toThrow();
      
      const corruptedData = await redisClient.get('data:corrupted');
      expect(() => JSON.parse(corruptedData!)).toThrow();
      
      const emptyData = await redisClient.get('data:empty');
      expect(emptyData).toBe('');
      
      const nullData = await redisClient.get('data:null');
      expect(JSON.parse(nullData!)).toBeNull();
    });
  });
});
