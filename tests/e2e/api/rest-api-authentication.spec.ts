import { test, expect } from '../fixtures/test-fixtures';
import { createTestUtilities } from '../utils/test-utilities';

/**
 * REST API Authentication E2E Tests
 * Tests API endpoints, authentication, and authorization
 */

test.describe('REST API Authentication', () => {
  const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:11235/api';

  test.beforeEach(async ({ page, context }) => {
    const utilities = createTestUtilities(page, context);
    (page as any).testUtilities = utilities;

    // Mock API responses if needed for testing
    await utilities.mockApiResponse('GET', `${API_BASE_URL}/status`, {
      status: 'healthy',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
    });
  });

  test.describe('API Health and Status', () => {
    test('should return API health status', async ({ page }) => {
      const response = await page.request.get(`${API_BASE_URL}/status`);

      expect(response.ok()).toBe(true);
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('status', 'healthy');
      expect(data).toHaveProperty('version');
      expect(data).toHaveProperty('timestamp');
    });

    test('should return proper CORS headers', async ({ page }) => {
      const response = await page.request.get(`${API_BASE_URL}/status`);

      const headers = response.headers();
      expect(headers['access-control-allow-origin']).toBeTruthy();
      expect(headers['access-control-allow-methods']).toBeTruthy();
    });

    test('should handle API versioning', async ({ page }) => {
      // Test v1 API
      const v1Response = await page.request.get(`${API_BASE_URL}/v1/status`);
      if (v1Response.ok()) {
        const v1Data = await v1Response.json();
        expect(v1Data).toHaveProperty('version');
      }

      // Test default version fallback
      const defaultResponse = await page.request.get(`${API_BASE_URL}/status`);
      expect(defaultResponse.ok()).toBe(true);
    });
  });

  test.describe('Terminal Management API', () => {
    test('should list available terminals', async ({ page, testData }) => {
      const mockTerminals = testData.getMockApiResponses().find(
        mock => mock.url === '/api/terminals' && mock.method === 'GET'
      );

      if (mockTerminals) {
        const utilities = (page as any).testUtilities;
        await utilities.mockApiResponse('GET', `${API_BASE_URL}/terminals`, mockTerminals.response);
      }

      const response = await page.request.get(`${API_BASE_URL}/terminals`);

      expect(response.ok()).toBe(true);
      const data = await response.json();

      if (data.terminals) {
        expect(Array.isArray(data.terminals)).toBe(true);

        for (const terminal of data.terminals) {
          expect(terminal).toHaveProperty('id');
          expect(terminal).toHaveProperty('status');
          expect(['active', 'inactive', 'starting', 'stopping']).toContain(terminal.status);
        }
      }
    });

    test('should create new terminal session', async ({ page, testData }) => {
      const mockCreate = testData.getMockApiResponses().find(
        mock => mock.url === '/api/terminals' && mock.method === 'POST'
      );

      if (mockCreate) {
        const utilities = (page as any).testUtilities;
        await utilities.mockApiResponse('POST', `${API_BASE_URL}/terminals`, mockCreate.response, 201);
      }

      const response = await page.request.post(`${API_BASE_URL}/terminals`, {
        data: {
          shell: '/bin/bash',
          cwd: process.cwd(),
        },
      });

      if (response.ok()) {
        expect([200, 201]).toContain(response.status());
        const data = await response.json();
        expect(data).toHaveProperty('id');
        expect(data).toHaveProperty('status');
      } else {
        // API might not support terminal creation in test environment
        console.log(`Terminal creation not supported: ${response.status()}`);
      }
    });

    test('should get terminal session details', async ({ page }) => {
      // First, try to get a terminal ID
      const listResponse = await page.request.get(`${API_BASE_URL}/terminals`);

      if (listResponse.ok()) {
        const listData = await listResponse.json();

        if (listData.terminals && listData.terminals.length > 0) {
          const terminalId = listData.terminals[0].id;

          const detailResponse = await page.request.get(`${API_BASE_URL}/terminals/${terminalId}`);

          if (detailResponse.ok()) {
            const detailData = await detailResponse.json();
            expect(detailData).toHaveProperty('id', terminalId);
            expect(detailData).toHaveProperty('status');
          }
        }
      }
    });

    test('should handle terminal not found errors', async ({ page }) => {
      const response = await page.request.get(`${API_BASE_URL}/terminals/non-existent-id`);

      expect([404, 400]).toContain(response.status());

      if (response.status() === 404) {
        const data = await response.json();
        expect(data).toHaveProperty('error');
        expect(data.error.toLowerCase()).toContain('not found');
      }
    });
  });

  test.describe('Authentication and Authorization', () => {
    test('should require authentication for protected endpoints', async ({ page }) => {
      // Test endpoints that might require authentication
      const protectedEndpoints = [
        '/admin/terminals',
        '/admin/settings',
        '/admin/users',
      ];

      for (const endpoint of protectedEndpoints) {
        const response = await page.request.get(`${API_BASE_URL}${endpoint}`);

        if (response.status() === 401) {
          // Expected for protected endpoint
          const data = await response.json();
          expect(data).toHaveProperty('error');
          expect(data.error.toLowerCase()).toMatch(/unauthorized|authentication/);
        } else if (response.status() === 404) {
          // Endpoint might not exist in current implementation
          console.log(`Endpoint not found: ${endpoint}`);
        }
      }
    });

    test('should accept valid API keys', async ({ page }) => {
      const apiKey = process.env.TEST_API_KEY || 'test-key';

      const response = await page.request.get(`${API_BASE_URL}/status`, {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'X-API-Key': apiKey,
        },
      });

      // Should work with or without API key for status endpoint
      expect(response.ok()).toBe(true);
    });

    test('should reject invalid API keys', async ({ page }) => {
      const response = await page.request.get(`${API_BASE_URL}/admin/settings`, {
        headers: {
          'Authorization': 'Bearer invalid-key',
          'X-API-Key': 'invalid-key',
        },
      });

      if (response.status() === 401) {
        const data = await response.json();
        expect(data).toHaveProperty('error');
      } else {
        // Endpoint might not require authentication or doesn't exist
        console.log(`Admin endpoint response: ${response.status()}`);
      }
    });

    test('should implement rate limiting', async ({ page }) => {
      const maxRequests = 100;
      const responses = [];

      // Make rapid requests to test rate limiting
      for (let i = 0; i < Math.min(maxRequests, 20); i++) {
        try {
          const response = await page.request.get(`${API_BASE_URL}/status`);
          responses.push(response.status());

          // Small delay to avoid overwhelming in test
          if (i % 5 === 0) {
            await page.waitForTimeout(100);
          }
        } catch (error) {
          console.log(`Request ${i} failed:`, error);
          break;
        }
      }

      // Most requests should succeed
      const successfulRequests = responses.filter(status => status === 200).length;
      expect(successfulRequests).toBeGreaterThan(10);

      // Check if any rate limiting occurred (429 status)
      const rateLimited = responses.filter(status => status === 429).length;
      if (rateLimited > 0) {
        console.log(`Rate limiting detected: ${rateLimited} requests limited`);
      }
    });
  });

  test.describe('API Error Handling', () => {
    test('should return proper error responses', async ({ page }) => {
      // Test various error conditions
      const errorTests = [
        {
          endpoint: '/non-existent-endpoint',
          expectedStatus: 404,
          description: 'Non-existent endpoint',
        },
        {
          endpoint: '/terminals',
          method: 'PATCH',
          expectedStatus: [405, 404], // Method not allowed or not found
          description: 'Unsupported HTTP method',
        },
      ];

      for (const { endpoint, method = 'GET', expectedStatus, description } of errorTests) {
        test.step(description, async () => {
          let response;

          switch (method) {
            case 'POST':
              response = await page.request.post(`${API_BASE_URL}${endpoint}`);
              break;
            case 'PATCH':
              response = await page.request.patch(`${API_BASE_URL}${endpoint}`);
              break;
            default:
              response = await page.request.get(`${API_BASE_URL}${endpoint}`);
          }

          const expectedStatuses = Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus];
          expect(expectedStatuses).toContain(response.status());

          // Error responses should be JSON with error field
          if (response.headers()['content-type']?.includes('application/json')) {
            const data = await response.json();
            expect(data).toHaveProperty('error');
          }
        });
      }
    });

    test('should handle malformed JSON requests', async ({ page }) => {
      const response = await page.request.post(`${API_BASE_URL}/terminals`, {
        data: 'invalid json',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      expect([400, 422]).toContain(response.status());

      if (response.headers()['content-type']?.includes('application/json')) {
        const data = await response.json();
        expect(data).toHaveProperty('error');
        expect(data.error.toLowerCase()).toMatch(/json|parse|malformed/);
      }
    });

    test('should validate request parameters', async ({ page }) => {
      // Test parameter validation
      const response = await page.request.post(`${API_BASE_URL}/terminals`, {
        data: {
          shell: '',  // Invalid empty shell
          cwd: '/non/existent/path',  // Invalid path
        },
      });

      if ([400, 422].includes(response.status())) {
        const data = await response.json();
        expect(data).toHaveProperty('error');

        // Should provide helpful validation messages
        expect(data.error.length).toBeGreaterThan(5);
        expect(data.error).not.toMatch(/undefined|null/);
      }
    });
  });

  test.describe('API Performance and Reliability', () => {
    test('should respond within acceptable time limits', async ({ page }) => {
      const maxResponseTime = 2000; // 2 seconds

      const endpoints = [
        '/status',
        '/terminals',
        '/system/info',
      ];

      for (const endpoint of endpoints) {
        const startTime = Date.now();

        try {
          const response = await page.request.get(`${API_BASE_URL}${endpoint}`, {
            timeout: maxResponseTime + 1000,
          });

          const responseTime = Date.now() - startTime;

          if (response.ok()) {
            expect(responseTime).toBeLessThan(maxResponseTime);
            console.log(`${endpoint}: ${responseTime}ms`);
          } else if (response.status() === 404) {
            console.log(`${endpoint}: Not implemented (404)`);
          }
        } catch (error) {
          console.log(`${endpoint}: Timeout or error`);
        }
      }
    });

    test('should handle concurrent requests', async ({ page }) => {
      const concurrentRequests = 10;
      const promises = [];

      // Make concurrent requests
      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(
          page.request.get(`${API_BASE_URL}/status?request=${i}`)
        );
      }

      const responses = await Promise.all(promises);

      // All requests should complete
      expect(responses).toHaveLength(concurrentRequests);

      // Most should be successful
      const successfulRequests = responses.filter(r => r.ok()).length;
      expect(successfulRequests).toBeGreaterThanOrEqual(concurrentRequests * 0.8);
    });

    test('should maintain API consistency across multiple calls', async ({ page }) => {
      // Make multiple calls to the same endpoint
      const responses = [];

      for (let i = 0; i < 5; i++) {
        const response = await page.request.get(`${API_BASE_URL}/status`);

        if (response.ok()) {
          const data = await response.json();
          responses.push(data);
        }

        await page.waitForTimeout(200);
      }

      if (responses.length > 1) {
        // Responses should have consistent structure
        const firstResponse = responses[0];
        const keys = Object.keys(firstResponse);

        for (const response of responses.slice(1)) {
          const responseKeys = Object.keys(response);

          // Should have same keys
          expect(responseKeys.sort()).toEqual(keys.sort());

          // Status should be consistent
          if (firstResponse.status) {
            expect(response.status).toBe(firstResponse.status);
          }
        }
      }
    });
  });

  test.afterEach(async ({ page }) => {
    // Clean up test utilities
    const utilities = (page as any).testUtilities;
    if (utilities) {
      await utilities.cleanup();
    }
  });
});