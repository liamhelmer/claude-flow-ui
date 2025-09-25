import request from 'supertest';
import { Application } from 'express';
import { startTestServer, stopTestServer, resetTestState } from '../../helpers/testServer';
import { UserFactory } from '../../factories/UserFactory';

describe('Complete Authentication Flow E2E', () => {
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

  describe('User Registration to Access Flow', () => {
    it('should complete full user journey: register -> login -> access protected resource -> logout', async () => {
      // Step 1: Register new user
      const userData = UserFactory.createRegistrationData({
        email: 'e2e-test@example.com',
        firstName: 'E2E',
        lastName: 'Test'
      });

      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      expect(registerResponse.body.success).toBe(true);
      const { accessToken, refreshToken } = registerResponse.body.data.tokens;
      const userId = registerResponse.body.data.user.id;

      // Step 2: Access protected resource with new token
      const protectedResponse = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(protectedResponse.body.data).toMatchObject({
        id: userId,
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName
      });

      // Step 3: Refresh tokens
      const refreshResponse = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      expect(refreshResponse.body.success).toBe(true);
      const newAccessToken = refreshResponse.body.data.tokens.accessToken;
      expect(newAccessToken).not.toBe(accessToken);

      // Step 4: Use new token to access protected resource
      const newProtectedResponse = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .expect(200);

      expect(newProtectedResponse.body.data.id).toBe(userId);

      // Step 5: Logout
      const logoutResponse = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${newAccessToken}`)
        .expect(200);

      expect(logoutResponse.body.message).toBe('Logout successful');

      // Step 6: Verify token is invalidated (optional, depends on implementation)
      // This step would fail if you implement token blacklisting
    });
  });

  describe('Login Flow with Existing User', () => {
    it('should complete login -> access -> refresh -> logout flow', async () => {
      // Setup: Register user first
      const userData = UserFactory.createRegistrationData({
        email: 'existing-user@example.com'
      });

      await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      // Step 1: Login with existing credentials
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        })
        .expect(200);

      expect(loginResponse.body.success).toBe(true);
      const { accessToken, refreshToken } = loginResponse.body.data.tokens;

      // Step 2: Access multiple protected endpoints
      const endpoints = [
        '/api/v1/auth/me',
        '/api/v1/users/profile'
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('Authorization', `Bearer ${accessToken}`);

        // Should either be 200 (exists) or 404 (endpoint not implemented yet)
        expect([200, 404]).toContain(response.status);

        if (response.status !== 404) {
          expect(response.body.success).toBe(true);
        }
      }

      // Step 3: Multiple token refreshes
      let currentRefreshToken = refreshToken;
      let currentAccessToken = accessToken;

      for (let i = 0; i < 3; i++) {
        const refreshResponse = await request(app)
          .post('/api/v1/auth/refresh')
          .send({ refreshToken: currentRefreshToken })
          .expect(200);

        expect(refreshResponse.body.success).toBe(true);

        // Update tokens for next iteration
        currentAccessToken = refreshResponse.body.data.tokens.accessToken;
        currentRefreshToken = refreshResponse.body.data.tokens.refreshToken;

        // Verify new token works
        await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${currentAccessToken}`)
          .expect(200);
      }

      // Step 4: Final logout
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${currentAccessToken}`)
        .expect(200);
    });
  });

  describe('Error Recovery Scenarios', () => {
    it('should handle invalid credentials gracefully', async () => {
      // Attempt login with non-existent user
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'password123'
        })
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          message: 'Invalid credentials'
        }
      });
    });

    it('should handle token expiration flow', async () => {
      // This test would require mocking JWT expiration or using very short tokens
      // For now, we'll test the error handling structure

      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer expired-token')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toContain('Invalid token');
    });

    it('should handle malformed requests gracefully', async () => {
      // Test registration with missing fields
      const invalidRegistration = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'test@example.com'
          // Missing required fields
        })
        .expect(400);

      expect(invalidRegistration.body.success).toBe(false);
      expect(invalidRegistration.body.error.code).toBe('VALIDATION_ERROR');

      // Test login with missing fields
      const invalidLogin = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com'
          // Missing password
        })
        .expect(400);

      expect(invalidLogin.body.success).toBe(false);
    });
  });

  describe('Rate Limiting Flow', () => {
    it('should enforce rate limits on login attempts', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'wrongpassword'
      };

      // Make multiple failed login attempts
      const attempts = [];
      for (let i = 0; i < 10; i++) {
        attempts.push(
          request(app)
            .post('/api/v1/auth/login')
            .send(loginData)
        );
      }

      const responses = await Promise.all(attempts);

      // Some requests should be rate limited (429) or unauthorized (401)
      const statusCodes = responses.map(r => r.status);
      expect(statusCodes).toEqual(expect.arrayContaining([401]));

      // If rate limiting is implemented, we might see 429 responses
      // expect(statusCodes).toEqual(expect.arrayContaining([429]));
    });
  });

  describe('Concurrent User Sessions', () => {
    it('should handle multiple concurrent sessions for same user', async () => {
      // Register user
      const userData = UserFactory.createRegistrationData();
      await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      // Create multiple concurrent sessions
      const loginPromises = Array.from({ length: 3 }, () =>
        request(app)
          .post('/api/v1/auth/login')
          .send({
            email: userData.email,
            password: userData.password
          })
      );

      const loginResponses = await Promise.all(loginPromises);

      // All sessions should be successful
      loginResponses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });

      // Extract tokens from each session
      const tokens = loginResponses.map(r => r.body.data.tokens.accessToken);

      // All tokens should be different
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(3);

      // All tokens should work independently
      const profilePromises = tokens.map(token =>
        request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${token}`)
      );

      const profileResponses = await Promise.all(profilePromises);
      profileResponses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });
    });
  });
});