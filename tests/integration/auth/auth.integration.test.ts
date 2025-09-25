import request from 'supertest';
import { Application } from 'express';
import { startTestServer, stopTestServer, getTestApp, resetTestState } from '../../helpers/testServer';
import { UserFactory } from '../../factories/UserFactory';
import { createTestUser } from '../../helpers/testDatabase';
import bcrypt from 'bcrypt';

describe('Auth Integration Tests', () => {
  let app: Application;

  beforeAll(async () => {
    app = await startTestServer();
  });

  afterAll(async () => {
    await stopTestServer();
  });

  beforeEach(async () => {
    await resetTestState();
  });

  describe('POST /api/v1/auth/register', () => {
    it('should register new user with valid data', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData();

      // Act
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      // Assert
      expect(response.body).toMatchObject({
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            email: userData.email,
            firstName: userData.firstName,
            lastName: userData.lastName
          },
          tokens: {
            accessToken: expect.any(String),
            refreshToken: expect.any(String)
          }
        }
      });
    });

    it('should reject registration with duplicate email', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData();
      await createTestUser({ email: userData.email });

      // Act
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(409);

      // Assert
      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: expect.stringContaining('already exists')
        }
      });
    });

    it('should reject registration with invalid email format', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData({
        email: 'invalid-email-format'
      });

      // Act
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(400);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should reject registration with weak password', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData({
        password: '123'
      });

      // Act
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(400);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toContain('password');
    });
  });

  describe('POST /api/v1/auth/login', () => {
    it('should login with valid credentials', async () => {
      // Arrange
      const password = 'Test123!@#';
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await createTestUser({
        email: 'test@example.com',
        password: hashedPassword,
        emailVerified: true,
        isActive: true
      });

      const loginData = {
        email: user.email,
        password: password
      };

      // Act
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email
          },
          tokens: {
            accessToken: expect.any(String),
            refreshToken: expect.any(String)
          }
        }
      });
    });

    it('should reject login with invalid email', async () => {
      // Arrange
      const loginData = UserFactory.createLoginData({
        email: 'nonexistent@example.com'
      });

      // Act
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(401);

      // Assert
      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: 'Invalid credentials'
        }
      });
    });

    it('should reject login with invalid password', async () => {
      // Arrange
      const user = await createTestUser({ email: 'test@example.com' });
      const loginData = {
        email: user.email,
        password: 'WrongPassword123'
      };

      // Act
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('Invalid credentials');
    });

    it('should reject login for unverified email', async () => {
      // Arrange
      const password = 'Test123!@#';
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await createTestUser({
        email: 'unverified@example.com',
        password: hashedPassword,
        emailVerified: false
      });

      const loginData = {
        email: user.email,
        password: password
      };

      // Act
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(403);

      // Assert
      expect(response.body.error.message).toContain('verify');
    });

    it('should reject login for inactive user', async () => {
      // Arrange
      const password = 'Test123!@#';
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await createTestUser({
        email: 'inactive@example.com',
        password: hashedPassword,
        emailVerified: true,
        isActive: false
      });

      const loginData = {
        email: user.email,
        password: password
      };

      // Act
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(403);

      // Assert
      expect(response.body.error.message).toContain('deactivated');
    });
  });

  describe('POST /api/v1/auth/refresh', () => {
    it('should refresh tokens with valid refresh token', async () => {
      // Arrange
      const password = 'Test123!@#';
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await createTestUser({
        email: 'test@example.com',
        password: hashedPassword,
        emailVerified: true,
        isActive: true
      });

      // Login to get refresh token
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: user.email,
          password: password
        });

      const refreshToken = loginResponse.body.data.tokens.refreshToken;

      // Act
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          tokens: {
            accessToken: expect.any(String),
            refreshToken: expect.any(String)
          }
        }
      });

      // New tokens should be different
      expect(response.body.data.tokens.accessToken)
        .not.toBe(loginResponse.body.data.tokens.accessToken);
    });

    it('should reject refresh with invalid token', async () => {
      // Act
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toContain('Invalid');
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    it('should logout successfully with valid token', async () => {
      // Arrange
      const password = 'Test123!@#';
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await createTestUser({
        email: 'test@example.com',
        password: hashedPassword,
        emailVerified: true,
        isActive: true
      });

      // Login to get access token
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: user.email,
          password: password
        });

      const accessToken = loginResponse.body.data.tokens.accessToken;

      // Act
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        success: true,
        message: 'Logout successful'
      });
    });

    it('should reject logout without token', async () => {
      // Act
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('Access token required');
    });
  });

  describe('GET /api/v1/auth/me', () => {
    it('should return current user with valid token', async () => {
      // Arrange
      const password = 'Test123!@#';
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await createTestUser({
        email: 'test@example.com',
        password: hashedPassword,
        firstName: 'Test',
        lastName: 'User',
        emailVerified: true,
        isActive: true
      });

      // Login to get access token
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: user.email,
          password: password
        });

      const accessToken = loginResponse.body.data.tokens.accessToken;

      // Act
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      // Assert
      expect(response.body).toMatchObject({
        success: true,
        data: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isActive: user.isActive,
          emailVerified: user.emailVerified
        }
      });

      // Should not include sensitive data
      expect(response.body.data.password).toBeUndefined();
    });

    it('should reject request without token', async () => {
      // Act
      const response = await request(app)
        .get('/api/v1/auth/me')
        .expect(401);

      // Assert
      expect(response.body.success).toBe(false);
    });
  });
});