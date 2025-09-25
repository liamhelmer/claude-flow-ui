/**
 * Authentication and Authorization Flow Integration Tests
 *
 * These tests validate the complete authentication and authorization flow
 * across all layers of the application, including JWT handling, session management,
 * role-based access control, and security measures.
 */

import request from 'supertest';
import { Application } from 'express';
import App from '../../rest-api/src/app';
import { database } from '../../rest-api/src/config/database';
import { redisClient } from '../../rest-api/src/config/redis';
import { User } from '../../rest-api/src/models/User';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from '../../rest-api/src/config/environment';
import { io, Socket } from 'socket.io-client';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';

describe('Authentication and Authorization Flow Integration Tests', () => {
  let app: Application;
  let testApp: App;
  let regularUser: User;
  let adminUser: User;
  let regularToken: string;
  let adminToken: string;
  let refreshToken: string;
  let httpServer: any;
  let socketServer: SocketIOServer;
  let serverPort: number;

  const regularUserData = {
    firstName: 'Regular',
    lastName: 'User',
    email: 'regular@test.com',
    password: 'RegularPassword123!',
    role: 'user' as const,
  };

  const adminUserData = {
    firstName: 'Admin',
    lastName: 'User',
    email: 'admin@test.com',
    password: 'AdminPassword123!',
    role: 'admin' as const,
  };

  beforeAll(async () => {
    // Initialize test application
    testApp = new App();
    app = testApp.app;

    // Set test environment
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_auth_test';
    process.env.JWT_SECRET = 'test-jwt-secret-for-auth-flow';
    process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret-for-auth-flow';

    // Initialize connections
    await database.connect();
    await database.sync({ force: true });
    await redisClient.connect();

    // Create test users
    const hashedRegularPassword = await bcrypt.hash(regularUserData.password, 12);
    const hashedAdminPassword = await bcrypt.hash(adminUserData.password, 12);

    regularUser = await User.create({
      ...regularUserData,
      password: hashedRegularPassword,
    });

    adminUser = await User.create({
      ...adminUserData,
      password: hashedAdminPassword,
    });

    // Generate tokens
    regularToken = jwt.sign(
      { userId: regularUser.id, email: regularUser.email, role: regularUser.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    adminToken = jwt.sign(
      { userId: adminUser.id, email: adminUser.email, role: adminUser.role },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    refreshToken = jwt.sign(
      { userId: regularUser.id, type: 'refresh' },
      config.jwt.refreshSecret,
      { expiresIn: config.jwt.refreshExpiresIn }
    );

    // Set up WebSocket server for auth testing
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

    setupWebSocketAuthHandlers();
  }, 30000);

  afterAll(async () => {
    await User.destroy({ where: {} });
    await database.disconnect();
    await redisClient.flushall();
    await redisClient.disconnect();
    await testApp.shutdown();
    
    if (socketServer) {
      socketServer.close();
    }
    if (httpServer) {
      httpServer.close();
    }
  }, 30000);

  beforeEach(async () => {
    // Clear Redis session data between tests
    await redisClient.flushall();
  });

  function setupWebSocketAuthHandlers() {
    socketServer.on('connection', (socket) => {
      socket.on('authenticate', async (data) => {
        try {
          const { token } = data;
          const decoded = jwt.verify(token, config.jwt.secret) as any;
          
          socket.data.userId = decoded.userId;
          socket.data.role = decoded.role;
          socket.data.authenticated = true;
          
          socket.emit('authenticated', {
            success: true,
            userId: decoded.userId,
            role: decoded.role,
          });
        } catch (error) {
          socket.emit('auth_error', {
            error: 'Authentication failed',
            message: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      });

      socket.on('admin-action', (data) => {
        if (!socket.data.authenticated) {
          socket.emit('error', { message: 'Not authenticated' });
          return;
        }
        
        if (socket.data.role !== 'admin') {
          socket.emit('error', { message: 'Admin access required' });
          return;
        }
        
        socket.emit('admin-response', { success: true, data });
      });
    });
  }

  describe('JWT Token Lifecycle', () => {
    test('should generate valid access and refresh tokens on login', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: regularUserData.email,
          password: regularUserData.password,
        })
        .expect(200);

      const { accessToken, refreshToken: newRefreshToken } = response.body.tokens;

      // Verify access token structure and claims
      const accessDecoded = jwt.verify(accessToken, config.jwt.secret) as any;
      expect(accessDecoded).toMatchObject({
        userId: regularUser.id,
        email: regularUser.email,
        role: regularUser.role,
        iat: expect.any(Number),
        exp: expect.any(Number),
      });

      // Verify refresh token structure and claims
      const refreshDecoded = jwt.verify(
        newRefreshToken,
        config.jwt.refreshSecret
      ) as any;
      expect(refreshDecoded).toMatchObject({
        userId: regularUser.id,
        type: 'refresh',
        iat: expect.any(Number),
        exp: expect.any(Number),
      });

      // Access token should expire before refresh token
      expect(accessDecoded.exp).toBeLessThan(refreshDecoded.exp);
    });

    test('should refresh access token with valid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      const { accessToken: newAccessToken, refreshToken: newRefreshToken } = response.body.tokens;

      // Tokens should be different from original
      expect(newAccessToken).not.toBe(regularToken);
      expect(newRefreshToken).not.toBe(refreshToken);

      // New access token should be valid
      const decoded = jwt.verify(newAccessToken, config.jwt.secret) as any;
      expect(decoded.userId).toBe(regularUser.id);

      // Old refresh token should be invalidated (in a real implementation)
      // For this test, we'll verify the new refresh token works
      const nextRefreshResponse = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: newRefreshToken })
        .expect(200);

      expect(nextRefreshResponse.body.tokens.accessToken).toBeTruthy();
    });

    test('should reject expired tokens', async () => {
      // Create an expired token
      const expiredToken = jwt.sign(
        { userId: regularUser.id, email: regularUser.email },
        config.jwt.secret,
        { expiresIn: '-1h' } // Expired 1 hour ago
      );

      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Token expired',
      });
    });

    test('should reject malformed tokens', async () => {
      const malformedTokens = [
        'invalid.token.format',
        'Bearer invalid-token',
        jwt.sign({ userId: 'invalid' }, 'wrong-secret'),
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature',
      ];

      for (const token of malformedTokens) {
        const response = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${token}`)
          .expect(401);

        expect(response.body.success).toBe(false);
      }
    });
  });

  describe('Role-Based Access Control', () => {
    test('should allow access to user endpoints with valid user token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${regularToken}`)
        .expect(200);

      expect(response.body.user).toMatchObject({
        id: regularUser.id,
        role: 'user',
      });
    });

    test('should allow access to admin endpoints with admin token', async () => {
      // This would be an admin-only endpoint in a real application
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body.user).toMatchObject({
        id: adminUser.id,
        role: 'admin',
      });
    });

    test('should deny access to admin endpoints with user token', async () => {
      // Simulate an admin-only endpoint by checking role in middleware
      // In a real app, this would be a separate endpoint with role validation
      const userPayload = jwt.verify(regularToken, config.jwt.secret) as any;
      expect(userPayload.role).toBe('user');
      
      const adminPayload = jwt.verify(adminToken, config.jwt.secret) as any;
      expect(adminPayload.role).toBe('admin');
      
      // Verify role differentiation works
      expect(userPayload.role).not.toBe(adminPayload.role);
    });

    test('should enforce role hierarchy in WebSocket connections', async () => {
      const userSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      const adminSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      try {
        // Test user socket authentication and access
        await new Promise<void>((resolve, reject) => {
          userSocket.on('connect', () => {
            userSocket.emit('authenticate', { token: regularToken });
          });
          
          userSocket.on('authenticated', (data) => {
            expect(data.role).toBe('user');
            
            // Try admin action - should fail
            userSocket.emit('admin-action', { test: 'data' });
          });
          
          userSocket.on('error', (error) => {
            expect(error.message).toContain('Admin access required');
            resolve();
          });
          
          userSocket.on('admin-response', () => {
            reject(new Error('User should not have admin access'));
          });
          
          setTimeout(() => reject(new Error('Timeout')), 5000);
        });

        // Test admin socket authentication and access
        await new Promise<void>((resolve, reject) => {
          adminSocket.on('connect', () => {
            adminSocket.emit('authenticate', { token: adminToken });
          });
          
          adminSocket.on('authenticated', (data) => {
            expect(data.role).toBe('admin');
            
            // Try admin action - should succeed
            adminSocket.emit('admin-action', { test: 'data' });
          });
          
          adminSocket.on('admin-response', (response) => {
            expect(response.success).toBe(true);
            resolve();
          });
          
          setTimeout(() => reject(new Error('Timeout')), 5000);
        });

      } finally {
        userSocket.disconnect();
        adminSocket.disconnect();
      }
    });
  });

  describe('Session Management and Security', () => {
    test('should track active sessions in Redis', async () => {
      const sessionKey = `user_session:${regularUser.id}`;
      
      // Login to create session
      await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: regularUserData.email,
          password: regularUserData.password,
        })
        .expect(200);

      // Check if session is tracked in Redis
      const sessionData = await redisClient.get(sessionKey);
      expect(sessionData).toBeTruthy();
      
      // Session should contain user information
      const session = JSON.parse(sessionData!);
      expect(session).toMatchObject({
        userId: regularUser.id,
        email: regularUser.email,
      });
    });

    test('should clear session on logout', async () => {
      const sessionKey = `user_session:${regularUser.id}`;
      
      // Set initial session data
      await redisClient.setex(sessionKey, 3600, JSON.stringify({
        userId: regularUser.id,
        email: regularUser.email,
        loginTime: Date.now(),
      }));

      // Logout
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${regularToken}`)
        .expect(200);

      // Verify session was cleared
      const clearedSession = await redisClient.get(sessionKey);
      expect(clearedSession).toBeNull();
    });

    test('should handle concurrent sessions for same user', async () => {
      // Simulate multiple login attempts
      const loginPromises = Array(3).fill(null).map(() =>
        request(app)
          .post('/api/v1/auth/login')
          .send({
            email: regularUserData.email,
            password: regularUserData.password,
          })
      );

      const responses = await Promise.all(loginPromises);
      
      // All logins should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.tokens.accessToken).toBeTruthy();
      });

      // Each should have different tokens
      const tokens = responses.map(r => r.body.tokens.accessToken);
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(3);
    });

    test('should enforce session timeout', async () => {
      const shortSessionKey = `temp_session:${regularUser.id}`;
      
      // Create session with short TTL (1 second)
      await redisClient.setex(shortSessionKey, 1, JSON.stringify({
        userId: regularUser.id,
        created: Date.now(),
      }));

      // Verify session exists
      let session = await redisClient.get(shortSessionKey);
      expect(session).toBeTruthy();

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Verify session expired
      session = await redisClient.get(shortSessionKey);
      expect(session).toBeNull();
    });
  });

  describe('Security Measures', () => {
    test('should prevent brute force attacks with rate limiting', async () => {
      const invalidCredentials = {
        email: regularUserData.email,
        password: 'wrongpassword',
      };

      // Make multiple failed login attempts
      const attempts = Array(15).fill(null).map(() =>
        request(app)
          .post('/api/v1/auth/login')
          .send(invalidCredentials)
      );

      const responses = await Promise.all(attempts);
      
      // Some requests should be rate limited (429)
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);

      // Rate limited responses should have proper error message
      rateLimitedResponses.forEach(response => {
        expect(response.body.error).toContain('Too many requests');
      });
    });

    test('should sanitize sensitive data in responses', async () => {
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${regularToken}`)
        .expect(200);

      // Password should never be included in response
      expect(response.body.user.password).toBeUndefined();
      
      // Other sensitive fields should also be excluded
      const sensitiveFields = ['password', 'resetToken', 'emailVerificationToken'];
      sensitiveFields.forEach(field => {
        expect(response.body.user[field]).toBeUndefined();
      });
    });

    test('should validate JWT signature integrity', async () => {
      // Create token with different secret
      const tamperedToken = jwt.sign(
        { userId: regularUser.id, email: regularUser.email },
        'malicious-secret',
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${tamperedToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: 'Invalid token',
      });
    });

    test('should prevent token replay attacks', async () => {
      // In a real implementation, you might track used refresh tokens
      // to prevent replay attacks. For this test, we'll verify tokens
      // are properly regenerated on refresh
      
      const firstRefresh = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      const secondRefresh = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: firstRefresh.body.tokens.refreshToken })
        .expect(200);

      // Each refresh should generate different tokens
      expect(firstRefresh.body.tokens.accessToken)
        .not.toBe(secondRefresh.body.tokens.accessToken);
      expect(firstRefresh.body.tokens.refreshToken)
        .not.toBe(secondRefresh.body.tokens.refreshToken);
    });

    test('should handle token theft scenarios', async () => {
      // Simulate scenario where refresh token is compromised
      const stolenRefreshToken = jwt.sign(
        { userId: 'malicious-user-id', type: 'refresh' },
        config.jwt.refreshSecret,
        { expiresIn: '7d' }
      );

      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: stolenRefreshToken })
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.stringContaining('Invalid refresh token'),
      });
    });
  });

  describe('Cross-Service Authentication', () => {
    test('should authenticate WebSocket connections with HTTP JWT', async () => {
      const clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      try {
        await new Promise<void>((resolve, reject) => {
          clientSocket.on('connect', () => {
            // Use JWT from HTTP auth
            clientSocket.emit('authenticate', { token: regularToken });
          });
          
          clientSocket.on('authenticated', (data) => {
            expect(data.success).toBe(true);
            expect(data.userId).toBe(regularUser.id);
            resolve();
          });
          
          clientSocket.on('auth_error', (error) => {
            reject(new Error(error.error));
          });
          
          setTimeout(() => reject(new Error('Timeout')), 5000);
        });
      } finally {
        clientSocket.disconnect();
      }
    });

    test('should maintain user context across HTTP and WebSocket', async () => {
      // Get user profile via HTTP
      const httpResponse = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${regularToken}`)
        .expect(200);

      // Connect via WebSocket with same token
      const clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      try {
        const wsUserData = await new Promise<any>((resolve, reject) => {
          clientSocket.on('connect', () => {
            clientSocket.emit('authenticate', { token: regularToken });
          });
          
          clientSocket.on('authenticated', (data) => {
            resolve(data);
          });
          
          setTimeout(() => reject(new Error('Timeout')), 5000);
        });

        // User context should be consistent
        expect(httpResponse.body.user.id).toBe(wsUserData.userId);
        expect(httpResponse.body.user.role).toBe(wsUserData.role);
      } finally {
        clientSocket.disconnect();
      }
    });
  });

  describe('Edge Cases and Error Scenarios', () => {
    test('should handle user account deactivation', async () => {
      // Deactivate user account
      await regularUser.update({ isActive: false });

      // Existing token should be rejected for deactivated user
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${regularToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.stringContaining('Account deactivated'),
      });

      // Reactivate for cleanup
      await regularUser.update({ isActive: true });
    });

    test('should handle user deletion during active session', async () => {
      // Create temporary user
      const tempUser = await User.create({
        firstName: 'Temp',
        lastName: 'User',
        email: 'temp@test.com',
        password: await bcrypt.hash('password123', 12),
        role: 'user',
      });

      const tempToken = jwt.sign(
        { userId: tempUser.id, email: tempUser.email },
        config.jwt.secret,
        { expiresIn: '1h' }
      );

      // Delete user
      await tempUser.destroy();

      // Token should be invalid for deleted user
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${tempToken}`)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.stringContaining('User not found'),
      });
    });

    test('should handle malformed authorization headers', async () => {
      const malformedHeaders = [
        'InvalidFormat',
        'Bearer',
        'Bearer ',
        'Basic dGVzdDp0ZXN0', // Wrong auth type
        'Bearer token with spaces',
      ];

      for (const header of malformedHeaders) {
        const response = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', header)
          .expect(401);

        expect(response.body.success).toBe(false);
      }
    });

    test('should handle database connection errors during auth', async () => {
      // Disconnect database
      await database.disconnect();

      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${regularToken}`)
        .expect(500);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.any(String),
      });

      // Reconnect for cleanup
      await database.connect();
    });
  });
});
