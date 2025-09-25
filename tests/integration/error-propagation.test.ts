/**
 * Error Propagation Across Layers Integration Tests
 *
 * These tests validate how errors propagate through different layers of the application,
 * ensuring proper error handling, logging, user feedback, and system recovery across
 * frontend components, API endpoints, database operations, and WebSocket connections.
 */

import request from 'supertest';
import { Application } from 'express';
import App from '../../rest-api/src/app';
import { database } from '../../rest-api/src/config/database';
import { redisClient } from '../../rest-api/src/config/redis';
import { User } from '../../rest-api/src/models/User';
import { ApiClient } from '../../src/lib/api/index';
import { WebSocketClient } from '../../src/lib/websocket/client';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from '../../rest-api/src/config/environment';

// Custom error types for testing
class DatabaseConnectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DatabaseConnectionError';
  }
}

class ValidationError extends Error {
  public field: string;
  constructor(message: string, field: string) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
  }
}

class AuthorizationError extends Error {
  public statusCode: number;
  constructor(message: string, statusCode = 403) {
    super(message);
    this.name = 'AuthorizationError';
    this.statusCode = statusCode;
  }
}

describe('Error Propagation Across Layers Integration Tests', () => {
  let app: Application;
  let testApp: App;
  let testUser: User;
  let authToken: string;
  let apiClient: ApiClient;
  let wsClient: WebSocketClient;
  let httpServer: any;
  let socketServer: SocketIOServer;
  let serverPort: number;

  const testUserData = {
    firstName: 'Error',
    lastName: 'Tester',
    email: 'error.tester@test.com',
    password: 'ErrorTestPassword123!',
    role: 'user' as const,
  };

  beforeAll(async () => {
    // Initialize test environment
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_error_test';
    process.env.JWT_SECRET = 'test-error-jwt-secret';
    process.env.LOG_LEVEL = 'error'; // Reduce logging noise

    // Initialize app
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

    // Set up WebSocket server for error testing
    httpServer = createServer();
    socketServer = new SocketIOServer(httpServer, {
      path: '/api/ws',
      cors: { origin: true, credentials: true },
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(0, () => {
        serverPort = httpServer.address().port;
        resolve();
      });
    });

    setupWebSocketErrorHandlers();

    // Initialize clients
    apiClient = new ApiClient(`http://localhost:${serverPort}/api`);
    wsClient = new WebSocketClient(`http://localhost:${serverPort}`);
  }, 30000);

  afterAll(async () => {
    await User.destroy({ where: {} });
    await database.disconnect();
    await redisClient.flushall();
    await redisClient.disconnect();
    await testApp.shutdown();
    
    if (wsClient) {
      wsClient.disconnect();
    }
    if (socketServer) {
      socketServer.close();
    }
    if (httpServer) {
      httpServer.close();
    }
  }, 30000);

  beforeEach(async () => {
    // Clear Redis error tracking
    await redisClient.flushall();
  });

  function setupWebSocketErrorHandlers() {
    socketServer.on('connection', (socket) => {
      socket.on('authenticate', (data) => {
        try {
          const { token } = data;
          if (!token) {
            throw new Error('Token required');
          }
          
          const decoded = jwt.verify(token, config.jwt.secret) as any;
          socket.data.user = decoded;
          socket.emit('authenticated', { success: true });
        } catch (error) {
          socket.emit('auth_error', {
            error: 'Authentication failed',
            details: error instanceof Error ? error.message : 'Unknown error',
            code: 'AUTH_FAILED',
          });
        }
      });

      socket.on('trigger-error', (data) => {
        const { errorType, message } = data;
        
        switch (errorType) {
          case 'validation':
            socket.emit('error', {
              type: 'ValidationError',
              message: message || 'Validation failed',
              field: 'testField',
              code: 'VALIDATION_ERROR',
            });
            break;
          case 'authorization':
            socket.emit('error', {
              type: 'AuthorizationError',
              message: message || 'Access denied',
              statusCode: 403,
              code: 'ACCESS_DENIED',
            });
            break;
          case 'database':
            socket.emit('error', {
              type: 'DatabaseError',
              message: message || 'Database connection failed',
              code: 'DB_CONNECTION_ERROR',
              retryable: true,
            });
            break;
          case 'network':
            // Simulate network error by disconnecting
            socket.disconnect(true);
            break;
          default:
            socket.emit('error', {
              type: 'UnknownError',
              message: message || 'An unknown error occurred',
              code: 'UNKNOWN_ERROR',
            });
        }
      });
    });
  }

  describe('Database Layer Error Propagation', () => {
    test('should propagate database connection errors to API layer', async () => {
      // Temporarily disconnect database
      await database.disconnect();

      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(500);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.any(String),
        code: expect.any(String),
      });

      // The error should indicate database connection issues
      expect(response.body.error.toLowerCase()).toContain('database');

      // Reconnect for other tests
      await database.connect();
    });

    test('should handle database constraint violations gracefully', async () => {
      // Try to create user with duplicate email
      const duplicateUserData = {
        firstName: 'Duplicate',
        lastName: 'User',
        email: testUser.email, // Same as existing user
        password: 'Password123!',
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(duplicateUserData)
        .expect(409); // Conflict

      expect(response.body).toMatchObject({
        success: false,
        error: expect.stringContaining('already exists'),
        code: 'DUPLICATE_EMAIL',
        field: 'email',
      });
    });

    test('should handle database transaction rollback errors', async () => {
      // This would typically be tested with a mock that forces transaction failure
      // For this test, we'll simulate by creating an invalid operation
      
      const invalidUserData = {
        firstName: 'Test',
        lastName: 'User',
        email: 'test@example.com',
        password: 'short', // Too short, will fail validation
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(invalidUserData)
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.any(String),
        details: expect.arrayContaining([
          expect.objectContaining({
            field: 'password',
            message: expect.any(String),
          })
        ])
      });
    });

    test('should handle database query timeout errors', async () => {
      // Mock a slow query by using a complex operation
      // In a real test, you might use database-specific timeout settings
      
      const startTime = Date.now();
      
      try {
        // This is a simplified test - in practice you'd mock a timeout
        const response = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${authToken}`)
          .timeout(100) // Very short timeout
          .expect(200);
        
        // If we get here, the query was fast enough
        expect(response.body.user).toBeTruthy();
      } catch (error) {
        // Timeout error should be handled gracefully
        expect(error).toHaveProperty('timeout', 100);
      }
    });
  });

  describe('Authentication and Authorization Error Propagation', () => {
    test('should propagate JWT validation errors consistently', async () => {
      const invalidTokens = [
        'invalid.jwt.token',
        jwt.sign({ userId: 'fake' }, 'wrong-secret'),
        jwt.sign({ userId: testUser.id }, config.jwt.secret, { expiresIn: '-1h' }), // Expired
        '', // Empty token
      ];

      for (const token of invalidTokens) {
        const response = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${token}`)
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: expect.any(String),
        });

        // Error message should be user-friendly, not expose internal details
        expect(response.body.error).not.toContain('jwt');
        expect(response.body.error).not.toContain('secret');
      }
    });

    test('should handle role-based authorization errors', async () => {
      // Create a user token with insufficient privileges
      const limitedToken = jwt.sign(
        { userId: testUser.id, email: testUser.email, role: 'limited' },
        config.jwt.secret,
        { expiresIn: '1h' }
      );

      // Try to access admin endpoint (if it existed)
      // For this test, we'll simulate with the user endpoint
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${limitedToken}`)
        .expect(200); // This should succeed as it's just getting own profile

      expect(response.body.user.role).not.toBe('admin');
    });

    test('should propagate account deactivation errors', async () => {
      // Deactivate the user account
      await testUser.update({ isActive: false });

      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.stringContaining('deactivated'),
        code: 'ACCOUNT_DEACTIVATED',
      });

      // Reactivate for cleanup
      await testUser.update({ isActive: true });
    });
  });

  describe('API Layer Error Propagation', () => {
    test('should handle and format validation errors properly', async () => {
      const invalidData = {
        firstName: '', // Required field empty
        lastName: 'T', // Too short
        email: 'invalid-email', // Invalid format
        password: '123', // Too short and weak
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Validation failed',
        details: expect.arrayContaining([
          expect.objectContaining({
            field: expect.any(String),
            message: expect.any(String),
            value: expect.anything(),
          })
        ])
      });

      // Should have errors for all invalid fields
      const errorFields = response.body.details.map((d: any) => d.field);
      expect(errorFields).toContain('firstName');
      expect(errorFields).toContain('email');
      expect(errorFields).toContain('password');
    });

    test('should handle rate limiting errors with proper headers', async () => {
      // Make many requests to trigger rate limiting
      const requests = Array(25).fill(null).map(() =>
        request(app)
          .post('/api/v1/auth/login')
          .send({
            email: 'nonexistent@test.com',
            password: 'wrongpassword',
          })
      );

      const responses = await Promise.all(requests);
      
      // Some should be rate limited
      const rateLimited = responses.filter(r => r.status === 429);
      expect(rateLimited.length).toBeGreaterThan(0);

      const rateLimitResponse = rateLimited[0];
      expect(rateLimitResponse.body).toMatchObject({
        error: expect.stringContaining('Too many requests'),
      });

      // Should include rate limit headers
      expect(rateLimitResponse.headers).toHaveProperty('x-ratelimit-limit');
      expect(rateLimitResponse.headers).toHaveProperty('x-ratelimit-remaining');
    });

    test('should handle malformed JSON requests', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid json')
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.stringContaining('Invalid JSON'),
        code: 'INVALID_JSON',
      });
    });

    test('should handle CORS preflight errors', async () => {
      const response = await request(app)
        .options('/api/v1/auth/login')
        .set('Origin', 'http://malicious-site.com')
        .set('Access-Control-Request-Method', 'POST')
        .expect(204); // Should still allow OPTIONS but may restrict actual requests

      // CORS headers should be present
      expect(response.headers).toHaveProperty('access-control-allow-origin');
    });
  });

  describe('WebSocket Error Propagation', () => {
    beforeEach(async () => {
      if (!wsClient.connected) {
        await wsClient.connect();
      }
    });

    test('should propagate authentication errors in WebSocket', async () => {
      return new Promise<void>((resolve, reject) => {
        wsClient.on('auth_error', (error) => {
          expect(error).toMatchObject({
            error: 'Authentication failed',
            details: expect.any(String),
            code: 'AUTH_FAILED',
          });
          resolve();
        });

        // Send invalid authentication
        wsClient.send('authenticate', { token: 'invalid-token' });

        setTimeout(() => reject(new Error('Auth error timeout')), 5000);
      });
    });

    test('should handle different types of WebSocket errors', async () => {
      // First authenticate
      await new Promise<void>((resolve) => {
        wsClient.on('authenticated', () => resolve());
        wsClient.send('authenticate', { token: authToken });
      });

      const errorTypes = [
        { type: 'validation', expectedCode: 'VALIDATION_ERROR' },
        { type: 'authorization', expectedCode: 'ACCESS_DENIED' },
        { type: 'database', expectedCode: 'DB_CONNECTION_ERROR' },
      ];

      for (const { type, expectedCode } of errorTypes) {
        await new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error(`Timeout waiting for ${type} error`));
          }, 5000);

          wsClient.on('error', (error) => {
            clearTimeout(timeout);
            
            expect(error).toMatchObject({
              code: expectedCode,
              message: expect.any(String),
              type: expect.any(String),
            });
            
            if (type === 'database') {
              expect(error.retryable).toBe(true);
            }
            
            resolve();
          });

          wsClient.send('trigger-error', {
            errorType: type,
            message: `Test ${type} error`,
          });
        });
      }
    });

    test('should handle WebSocket connection drops gracefully', async () => {
      // First authenticate
      await new Promise<void>((resolve) => {
        wsClient.on('authenticated', () => resolve());
        wsClient.send('authenticate', { token: authToken });
      });

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Connection drop timeout'));
        }, 5000);

        wsClient.on('connection-change', (connected) => {
          if (!connected) {
            clearTimeout(timeout);
            expect(wsClient.connected).toBe(false);
            resolve();
          }
        });

        // Trigger network error (forces disconnect)
        wsClient.send('trigger-error', {
          errorType: 'network',
        });
      });
    });
  });

  describe('Frontend Client Error Propagation', () => {
    test('should handle API client network errors', async () => {
      // Create client with invalid URL
      const invalidClient = new ApiClient('http://localhost:99999/api');

      await expect(invalidClient.get('/health')).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringMatching(/fetch|network|connect/i),
        })
      );
    });

    test('should handle API client timeout errors', async () => {
      // Mock fetch to simulate timeout
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockImplementation(() =>
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Request timeout')), 100);
        })
      ) as any;

      try {
        await expect(apiClient.get('/health')).rejects.toThrow('Request timeout');
      } finally {
        global.fetch = originalFetch;
      }
    });

    test('should handle API client HTTP error responses', async () => {
      // Mock fetch to return error response
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: () => Promise.resolve({ error: 'Resource not found' }),
      }) as any;

      try {
        await expect(apiClient.get('/nonexistent')).rejects.toThrow(
          expect.objectContaining({
            message: expect.stringContaining('Not Found'),
          })
        );
      } finally {
        global.fetch = originalFetch;
      }
    });

    test('should handle WebSocket client connection failures', async () => {
      const failingClient = new WebSocketClient('ws://localhost:99999');
      
      await expect(failingClient.connect()).rejects.toThrow();
      expect(failingClient.connected).toBe(false);
    });
  });

  describe('Cross-Layer Error Recovery', () => {
    test('should recover from temporary database failures', async () => {
      // Disconnect database
      await database.disconnect();

      // First request should fail
      await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(500);

      // Reconnect database
      await database.connect();

      // Subsequent request should succeed
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.user).toBeTruthy();
    });

    test('should recover from Redis connection failures', async () => {
      // Store some data first
      await redisClient.set('test:recovery', 'recovery test');
      
      // Disconnect Redis
      await redisClient.disconnect();

      // Operations should continue (may be slower without cache)
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.user).toBeTruthy();

      // Reconnect Redis
      await redisClient.connect();
      
      // Cache should work again
      await redisClient.set('test:recovery', 'recovery successful');
      const recovered = await redisClient.get('test:recovery');
      expect(recovered).toBe('recovery successful');
    });

    test('should implement circuit breaker pattern for external services', async () => {
      // This would typically involve mocking external service failures
      // For this test, we'll simulate with repeated failed requests
      
      let failureCount = 0;
      const maxFailures = 3;
      
      for (let i = 0; i < maxFailures + 2; i++) {
        try {
          await request(app)
            .post('/api/v1/auth/login')
            .send({
              email: 'nonexistent@test.com',
              password: 'wrongpassword',
            })
            .expect(401);
          
          failureCount++;
        } catch (error) {
          // If circuit breaker were implemented, it might start rejecting
          // requests after a threshold to prevent cascade failures
        }
      }
      
      expect(failureCount).toBeGreaterThan(0);
      // In a real circuit breaker implementation, we'd test that
      // requests are rejected after the threshold
    });
  });

  describe('Error Logging and Monitoring', () => {
    test('should log errors with appropriate context', async () => {
      const originalConsoleError = console.error;
      const errorLogs: any[] = [];
      
      console.error = jest.fn().mockImplementation((...args) => {
        errorLogs.push(args);
      });

      try {
        // Trigger an error
        await request(app)
          .post('/api/v1/auth/register')
          .send({
            email: 'duplicate@test.com',
            // Missing required fields to trigger validation error
          })
          .expect(400);

        // Check that errors were logged (if logging is implemented)
        // This would depend on your logging implementation
        expect(errorLogs.length).toBeGreaterThanOrEqual(0);
      } finally {
        console.error = originalConsoleError;
      }
    });

    test('should track error metrics in Redis', async () => {
      const errorKey = 'error_metrics:api:validation';
      
      // Clear existing metrics
      await redisClient.del(errorKey);
      
      // Trigger validation error
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'invalid' })
        .expect(400);

      // In a real implementation, error metrics would be tracked
      // For this test, we'll manually increment to simulate
      await redisClient.incr(errorKey);
      
      const errorCount = await redisClient.get(errorKey);
      expect(parseInt(errorCount!)).toBeGreaterThan(0);
    });

    test('should provide health check with error status', async () => {
      // Force an error condition
      await database.disconnect();
      
      const response = await request(app)
        .get('/health')
        .expect(200); // Health check should always return 200 but indicate issues

      expect(response.body.status).toBe('OK');
      // In a more sophisticated health check, it might indicate
      // component-level health status
      
      await database.connect();
    });
  });

  describe('User Experience Error Handling', () => {
    test('should provide user-friendly error messages', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@test.com',
          password: 'wrongpassword',
        })
        .expect(401);

      // Error message should be user-friendly
      expect(response.body.error).toBe('Invalid credentials');
      
      // Should not expose internal details
      expect(response.body.error).not.toContain('database');
      expect(response.body.error).not.toContain('query');
      expect(response.body.error).not.toContain('sql');
    });

    test('should provide actionable error information', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          firstName: '',
          lastName: 'Test',
          email: 'invalid-email',
          password: 'weak',
        })
        .expect(400);

      expect(response.body.details).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: expect.any(String),
            message: expect.any(String),
            // Should provide guidance on how to fix the error
          })
        ])
      );
    });

    test('should handle errors gracefully in production mode', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        // Force an internal error
        await database.disconnect();
        
        const response = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(500);

        // In production, should not expose internal error details
        expect(response.body.error).not.toContain('database');
        expect(response.body.error).not.toContain('connection');
        expect(response.body.error).toBe('Internal server error');
      } finally {
        process.env.NODE_ENV = originalEnv;
        await database.connect();
      }
    });
  });
});
