import request from 'supertest';
import { Application } from 'express';
import { startTestServer, stopTestServer, resetTestState } from '../helpers/testServer';
import { UserFactory } from '../factories/UserFactory';

describe('Authentication Performance Tests', () => {
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

  describe('Response Time Benchmarks', () => {
    it('should register user within performance threshold', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData();

      // Act & Assert
      const startTime = performance.now();
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);
      const endTime = performance.now();

      const responseTime = endTime - startTime;

      expect(response.body.success).toBe(true);
      expect(responseTime).toBeLessThan(1000); // Should complete within 1 second

      console.log(`Registration took ${responseTime.toFixed(2)}ms`);
    });

    it('should login within performance threshold', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData();
      await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      const loginData = {
        email: userData.email,
        password: userData.password
      };

      // Act & Assert
      const startTime = performance.now();
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(loginData)
        .expect(200);
      const endTime = performance.now();

      const responseTime = endTime - startTime;

      expect(response.body.success).toBe(true);
      expect(responseTime).toBeLessThan(500); // Should complete within 500ms

      console.log(`Login took ${responseTime.toFixed(2)}ms`);
    });

    it('should authenticate requests within performance threshold', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData();
      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      const accessToken = registerResponse.body.data.tokens.accessToken;

      // Act & Assert
      const startTime = performance.now();
      const response = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);
      const endTime = performance.now();

      const responseTime = endTime - startTime;

      expect(response.body.success).toBe(true);
      expect(responseTime).toBeLessThan(200); // Should complete within 200ms

      console.log(`Authentication took ${responseTime.toFixed(2)}ms`);
    });
  });

  describe('Concurrent Request Performance', () => {
    it('should handle concurrent registrations efficiently', async () => {
      // Arrange
      const concurrentUsers = 10;
      const users = Array.from({ length: concurrentUsers }, () =>
        UserFactory.createRegistrationData()
      );

      // Act
      const startTime = performance.now();
      const promises = users.map(userData =>
        request(app)
          .post('/api/v1/auth/register')
          .send(userData)
      );

      const responses = await Promise.all(promises);
      const endTime = performance.now();

      // Assert
      responses.forEach((response, index) => {
        expect(response.status).toBe(201);
        expect(response.body.success).toBe(true);
      });

      const totalTime = endTime - startTime;
      const avgTimePerRequest = totalTime / concurrentUsers;

      expect(avgTimePerRequest).toBeLessThan(2000); // Average should be under 2 seconds

      console.log(`${concurrentUsers} concurrent registrations took ${totalTime.toFixed(2)}ms total`);
      console.log(`Average time per registration: ${avgTimePerRequest.toFixed(2)}ms`);
    });

    it('should handle concurrent logins efficiently', async () => {
      // Arrange - Create users first
      const concurrentUsers = 10;
      const users = Array.from({ length: concurrentUsers }, () =>
        UserFactory.createRegistrationData()
      );

      // Register all users
      await Promise.all(users.map(userData =>
        request(app)
          .post('/api/v1/auth/register')
          .send(userData)
      ));

      // Act - Concurrent logins
      const startTime = performance.now();
      const loginPromises = users.map(userData =>
        request(app)
          .post('/api/v1/auth/login')
          .send({
            email: userData.email,
            password: userData.password
          })
      );

      const responses = await Promise.all(loginPromises);
      const endTime = performance.now();

      // Assert
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });

      const totalTime = endTime - startTime;
      const avgTimePerRequest = totalTime / concurrentUsers;

      expect(avgTimePerRequest).toBeLessThan(1000); // Average should be under 1 second

      console.log(`${concurrentUsers} concurrent logins took ${totalTime.toFixed(2)}ms total`);
      console.log(`Average time per login: ${avgTimePerRequest.toFixed(2)}ms`);
    });

    it('should handle concurrent authenticated requests efficiently', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData();
      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      const accessToken = registerResponse.body.data.tokens.accessToken;
      const concurrentRequests = 20;

      // Act
      const startTime = performance.now();
      const promises = Array.from({ length: concurrentRequests }, () =>
        request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${accessToken}`)
      );

      const responses = await Promise.all(promises);
      const endTime = performance.now();

      // Assert
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });

      const totalTime = endTime - startTime;
      const avgTimePerRequest = totalTime / concurrentRequests;

      expect(avgTimePerRequest).toBeLessThan(300); // Average should be under 300ms

      console.log(`${concurrentRequests} concurrent auth requests took ${totalTime.toFixed(2)}ms total`);
      console.log(`Average time per request: ${avgTimePerRequest.toFixed(2)}ms`);
    });
  });

  describe('Memory Usage Performance', () => {
    it('should not have significant memory leaks during auth operations', async () => {
      // Arrange
      const initialMemory = process.memoryUsage().heapUsed;
      const iterations = 100;

      // Act - Perform many auth operations
      for (let i = 0; i < iterations; i++) {
        const userData = UserFactory.createRegistrationData({
          email: `test-${i}@example.com`
        });

        await request(app)
          .post('/api/v1/auth/register')
          .send(userData);

        await request(app)
          .post('/api/v1/auth/login')
          .send({
            email: userData.email,
            password: userData.password
          });

        // Force garbage collection every 10 iterations
        if (i % 10 === 0 && global.gc) {
          global.gc();
        }
      }

      // Force final garbage collection
      if (global.gc) {
        global.gc();
      }

      // Assert
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      const memoryIncreasePerOperation = memoryIncrease / iterations;

      // Memory increase should be reasonable (less than 100KB per operation)
      expect(memoryIncreasePerOperation).toBeLessThan(100 * 1024);

      console.log(`Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB total`);
      console.log(`Memory per operation: ${(memoryIncreasePerOperation / 1024).toFixed(2)}KB`);
    });
  });

  describe('Database Performance', () => {
    it('should handle database operations efficiently under load', async () => {
      // Arrange
      const batchSize = 50;
      const batches = 5;

      // Act & Assert
      for (let batch = 0; batch < batches; batch++) {
        const users = Array.from({ length: batchSize }, (_, i) =>
          UserFactory.createRegistrationData({
            email: `batch-${batch}-user-${i}@example.com`
          })
        );

        const startTime = performance.now();
        const responses = await Promise.all(users.map(userData =>
          request(app)
            .post('/api/v1/auth/register')
            .send(userData)
        ));
        const endTime = performance.now();

        const batchTime = endTime - startTime;
        const avgTimePerUser = batchTime / batchSize;

        // All registrations should succeed
        responses.forEach(response => {
          expect(response.status).toBe(201);
        });

        // Performance should remain consistent across batches
        expect(avgTimePerUser).toBeLessThan(2000);

        console.log(`Batch ${batch + 1}: ${batchSize} users in ${batchTime.toFixed(2)}ms (avg: ${avgTimePerUser.toFixed(2)}ms per user)`);
      }
    });
  });

  describe('Token Operations Performance', () => {
    it('should handle token refresh operations efficiently', async () => {
      // Arrange
      const userData = UserFactory.createRegistrationData();
      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(userData);

      let refreshToken = registerResponse.body.data.tokens.refreshToken;
      const refreshIterations = 20;

      // Act & Assert
      const startTime = performance.now();

      for (let i = 0; i < refreshIterations; i++) {
        const refreshResponse = await request(app)
          .post('/api/v1/auth/refresh')
          .send({ refreshToken })
          .expect(200);

        expect(refreshResponse.body.success).toBe(true);
        refreshToken = refreshResponse.body.data.tokens.refreshToken;
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;
      const avgTimePerRefresh = totalTime / refreshIterations;

      expect(avgTimePerRefresh).toBeLessThan(300); // Should be under 300ms per refresh

      console.log(`${refreshIterations} token refreshes took ${totalTime.toFixed(2)}ms total`);
      console.log(`Average time per refresh: ${avgTimePerRefresh.toFixed(2)}ms`);
    });
  });
});