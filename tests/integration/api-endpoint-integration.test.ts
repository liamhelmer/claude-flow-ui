/**
 * REST API Endpoint Integration Tests
 *
 * These tests validate the complete request/response cycle of REST API endpoints,
 * including database interactions, authentication, validation, and error handling.
 */

import request from 'supertest';
import { Application } from 'express';
import App from '../../rest-api/src/app';
import { database } from '../../rest-api/src/config/database';
import { redisClient } from '../../rest-api/src/config/redis';
import { User } from '../../rest-api/src/models/User';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from '../../rest-api/src/config/environment';

describe('REST API Endpoint Integration Tests', () => {
  let app: Application;
  let testApp: App;
  let testUser: User;
  let authToken: string;

  // Test user data
  const testUserData = {
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@test.com',
    password: 'TestPassword123!',
    role: 'user',
  };

  beforeAll(async () => {
    // Initialize test application
    testApp = new App();
    app = testApp.app;

    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_test';
    process.env.JWT_SECRET = 'test-jwt-secret';
    process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret';

    // Initialize database and Redis connections
    await database.connect();
    await database.sync({ force: true }); // Clean slate for tests
    await redisClient.connect();

    // Create test user
    const hashedPassword = await bcrypt.hash(testUserData.password, 12);
    testUser = await User.create({
      ...testUserData,
      password: hashedPassword,
    });

    // Generate auth token for protected routes
    authToken = jwt.sign(
      { userId: testUser.id, email: testUser.email },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
  }, 30000);

  afterAll(async () => {
    // Clean up test data
    await User.destroy({ where: {} });
    await database.disconnect();
    await redisClient.flushall();
    await redisClient.disconnect();
    await testApp.shutdown();
  }, 30000);

  beforeEach(async () => {
    // Clear Redis cache between tests
    await redisClient.flushall();
  });

  describe('Health Check Endpoint', () => {
    test('should return health status with system information', async () => {
      const response = await request(app)
        .get('/health')
        .expect('Content-Type', /json/)
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'OK',
        timestamp: expect.stringMatching(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/),
        uptime: expect.any(Number),
        environment: 'test',
        version: expect.any(String),
      });

      expect(new Date(response.body.timestamp)).toBeInstanceOf(Date);
      expect(response.body.uptime).toBeGreaterThan(0);
    });

    test('should respond quickly for monitoring systems', async () => {
      const start = Date.now();
      await request(app).get('/health').expect(200);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(500); // Should respond within 500ms
    });
  });

  describe('Authentication Endpoints Integration', () => {
    describe('POST /api/v1/auth/register', () => {
      test('should create new user with hashed password in database', async () => {
        const newUserData = {
          firstName: 'Jane',
          lastName: 'Smith',
          email: 'jane.smith@test.com',
          password: 'SecurePassword123!',
        };

        const response = await request(app)
          .post('/api/v1/auth/register')
          .send(newUserData)
          .expect('Content-Type', /json/)
          .expect(201);

        expect(response.body).toMatchObject({
          success: true,
          message: 'User registered successfully',
          user: {
            id: expect.any(String),
            firstName: newUserData.firstName,
            lastName: newUserData.lastName,
            email: newUserData.email.toLowerCase(),
            role: 'user',
            isActive: true,
            createdAt: expect.any(String),
            updatedAt: expect.any(String),
          },
          tokens: {
            accessToken: expect.any(String),
            refreshToken: expect.any(String),
          },
        });

        // Verify user was created in database
        const dbUser = await User.findOne({
          where: { email: newUserData.email.toLowerCase() },
        });
        expect(dbUser).toBeTruthy();
        expect(dbUser?.firstName).toBe(newUserData.firstName);

        // Verify password was hashed
        expect(dbUser?.password).not.toBe(newUserData.password);
        const passwordValid = await bcrypt.compare(
          newUserData.password,
          dbUser!.password
        );
        expect(passwordValid).toBe(true);

        // Verify JWT token is valid
        const decoded = jwt.verify(
          response.body.tokens.accessToken,
          config.jwt.secret
        ) as any;
        expect(decoded.userId).toBe(dbUser?.id);
        expect(decoded.email).toBe(dbUser?.email);

        // Clean up
        await dbUser?.destroy();
      });

      test('should reject duplicate email registration', async () => {
        const duplicateData = {
          firstName: 'John',
          lastName: 'Duplicate',
          email: testUser.email, // Same email as existing user
          password: 'Password123!',
        };

        const response = await request(app)
          .post('/api/v1/auth/register')
          .send(duplicateData)
          .expect('Content-Type', /json/)
          .expect(409);

        expect(response.body).toMatchObject({
          success: false,
          error: expect.stringContaining('already exists'),
        });
      });

      test('should validate request body and return proper errors', async () => {
        const invalidData = {
          firstName: '', // Empty first name
          lastName: 'Test',
          email: 'invalid-email', // Invalid email format
          password: '123', // Too short password
        };

        const response = await request(app)
          .post('/api/v1/auth/register')
          .send(invalidData)
          .expect('Content-Type', /json/)
          .expect(400);

        expect(response.body).toMatchObject({
          success: false,
          error: expect.any(String),
          details: expect.any(Array),
        });

        expect(response.body.details).toContain(
          expect.objectContaining({
            field: 'firstName',
            message: expect.any(String),
          })
        );
      });
    });

    describe('POST /api/v1/auth/login', () => {
      test('should authenticate user and return valid tokens', async () => {
        const loginData = {
          email: testUser.email,
          password: testUserData.password,
        };

        const response = await request(app)
          .post('/api/v1/auth/login')
          .send(loginData)
          .expect('Content-Type', /json/)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          message: 'Login successful',
          user: {
            id: testUser.id,
            firstName: testUser.firstName,
            lastName: testUser.lastName,
            email: testUser.email,
            role: testUser.role,
          },
          tokens: {
            accessToken: expect.any(String),
            refreshToken: expect.any(String),
          },
        });

        // Verify tokens are valid JWT
        const accessDecoded = jwt.verify(
          response.body.tokens.accessToken,
          config.jwt.secret
        ) as any;
        expect(accessDecoded.userId).toBe(testUser.id);

        const refreshDecoded = jwt.verify(
          response.body.tokens.refreshToken,
          config.jwt.refreshSecret
        ) as any;
        expect(refreshDecoded.userId).toBe(testUser.id);

        // Verify lastLoginAt was updated in database
        await testUser.reload();
        expect(testUser.lastLoginAt).toBeTruthy();
      });

      test('should reject invalid credentials', async () => {
        const invalidLogin = {
          email: testUser.email,
          password: 'wrongpassword',
        };

        const response = await request(app)
          .post('/api/v1/auth/login')
          .send(invalidLogin)
          .expect('Content-Type', /json/)
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: 'Invalid credentials',
        });
      });

      test('should handle non-existent user', async () => {
        const nonExistentLogin = {
          email: 'nonexistent@test.com',
          password: 'password123',
        };

        const response = await request(app)
          .post('/api/v1/auth/login')
          .send(nonExistentLogin)
          .expect('Content-Type', /json/)
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: 'Invalid credentials',
        });
      });
    });

    describe('POST /api/v1/auth/refresh', () => {
      let refreshToken: string;

      beforeEach(async () => {
        // Generate a fresh refresh token for each test
        refreshToken = jwt.sign(
          { userId: testUser.id, type: 'refresh' },
          config.jwt.refreshSecret,
          { expiresIn: config.jwt.refreshExpiresIn }
        );
      });

      test('should generate new access token with valid refresh token', async () => {
        const response = await request(app)
          .post('/api/v1/auth/refresh')
          .send({ refreshToken })
          .expect('Content-Type', /json/)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          tokens: {
            accessToken: expect.any(String),
            refreshToken: expect.any(String),
          },
        });

        // Verify new tokens are valid and different
        const newAccessToken = response.body.tokens.accessToken;
        const newRefreshToken = response.body.tokens.refreshToken;

        expect(newAccessToken).not.toBe(authToken);
        expect(newRefreshToken).not.toBe(refreshToken);

        const decoded = jwt.verify(
          newAccessToken,
          config.jwt.secret
        ) as any;
        expect(decoded.userId).toBe(testUser.id);
      });

      test('should reject invalid refresh token', async () => {
        const response = await request(app)
          .post('/api/v1/auth/refresh')
          .send({ refreshToken: 'invalid-token' })
          .expect('Content-Type', /json/)
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: 'Invalid refresh token',
        });
      });
    });

    describe('POST /api/v1/auth/logout', () => {
      test('should invalidate tokens and clear Redis cache', async () => {
        // Set some data in Redis for the user (simulating active session)
        await redisClient.set(`user_session:${testUser.id}`, 'active');

        const response = await request(app)
          .post('/api/v1/auth/logout')
          .set('Authorization', `Bearer ${authToken}`)
          .expect('Content-Type', /json/)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          message: 'Logout successful',
        });

        // Verify session was cleared from Redis
        const sessionData = await redisClient.get(`user_session:${testUser.id}`);
        expect(sessionData).toBeNull();
      });
    });

    describe('GET /api/v1/auth/me', () => {
      test('should return current user profile with valid token', async () => {
        const response = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${authToken}`)
          .expect('Content-Type', /json/)
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          user: {
            id: testUser.id,
            firstName: testUser.firstName,
            lastName: testUser.lastName,
            email: testUser.email,
            role: testUser.role,
            isActive: testUser.isActive,
            fullName: `${testUser.firstName} ${testUser.lastName}`,
            createdAt: expect.any(String),
            updatedAt: expect.any(String),
          },
        });

        // Ensure password is not included
        expect(response.body.user.password).toBeUndefined();
      });

      test('should reject request without authentication token', async () => {
        const response = await request(app)
          .get('/api/v1/auth/me')
          .expect('Content-Type', /json/)
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: 'Access denied. No token provided',
        });
      });

      test('should reject request with invalid token', async () => {
        const response = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', 'Bearer invalid-token')
          .expect('Content-Type', /json/)
          .expect(401);

        expect(response.body).toMatchObject({
          success: false,
          error: 'Invalid token',
        });
      });
    });
  });

  describe('Rate Limiting Integration', () => {
    test('should enforce rate limits on login attempts', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      // Make multiple requests to trigger rate limit
      const requests = Array(10).fill(null).map(() =>
        request(app)
          .post('/api/v1/auth/login')
          .send(loginData)
      );

      const responses = await Promise.all(requests);
      
      // Some requests should be rate limited
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);

      const rateLimitResponse = rateLimitedResponses[0];
      expect(rateLimitResponse.body).toMatchObject({
        error: expect.stringContaining('Too many requests'),
      });
    });
  });

  describe('CORS Integration', () => {
    test('should handle preflight OPTIONS requests', async () => {
      const response = await request(app)
        .options('/api/v1/auth/login')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type,Authorization')
        .expect(204);

      expect(response.headers['access-control-allow-origin']).toBeTruthy();
      expect(response.headers['access-control-allow-methods']).toContain('POST');
      expect(response.headers['access-control-allow-headers']).toContain('Content-Type');
    });
  });

  describe('Error Handling Integration', () => {
    test('should handle database connection errors gracefully', async () => {
      // Temporarily close database connection
      await database.disconnect();

      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/)
        .expect(500);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.any(String),
      });

      // Reconnect for other tests
      await database.connect();
    });

    test('should handle malformed JSON requests', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .set('Content-Type', 'application/json')
        .send('invalid json {')
        .expect('Content-Type', /json/)
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: expect.stringContaining('Invalid JSON'),
      });
    });
  });

  describe('404 Route Handling', () => {
    test('should return proper 404 for non-existent routes', async () => {
      const response = await request(app)
        .get('/api/v1/nonexistent')
        .expect('Content-Type', /json/)
        .expect(404);

      expect(response.body).toMatchObject({
        error: 'Route not found',
        path: '/api/v1/nonexistent',
        method: 'GET',
      });
    });

    test('should handle 404 for different HTTP methods', async () => {
      const methods = ['POST', 'PUT', 'DELETE', 'PATCH'] as const;
      
      for (const method of methods) {
        const response = await request(app)
          [method.toLowerCase() as keyof typeof request](app)
          ('/api/v1/nonexistent')
          .expect('Content-Type', /json/)
          .expect(404);

        expect(response.body.method).toBe(method);
      }
    });
  });
});
