/**
 * API Security Tests
 *
 * Comprehensive security tests for REST API endpoints including:
 * - Rate limiting and DoS protection
 * - CORS policy enforcement
 * - HTTP method validation
 * - Authorization and access control
 * - API versioning security
 * - Request/Response header security
 * - Parameter pollution prevention
 * - Mass assignment prevention
 */

import { test, expect, describe, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import express from 'express';

class ApiSecurityTestSuite {
  static createMockApiServer() {
    const app = express();
    app.use(express.json({ limit: '1mb' }));
    app.use(express.urlencoded({ extended: true, limit: '1mb' }));
    
    // Mock rate limiter
    const rateLimitStore = new Map();
    const rateLimit = (maxRequests: number, windowMs: number) => {
      return (req: any, res: any, next: any) => {
        const key = req.ip || 'unknown';
        const now = Date.now();
        
        if (!rateLimitStore.has(key)) {
          rateLimitStore.set(key, []);
        }
        
        const requests = rateLimitStore.get(key);
        const recentRequests = requests.filter((time: number) => now - time < windowMs);
        
        if (recentRequests.length >= maxRequests) {
          return res.status(429).json({ error: 'Rate limit exceeded' });
        }
        
        recentRequests.push(now);
        rateLimitStore.set(key, recentRequests);
        next();
      };
    };
    
    // Mock CORS middleware
    const corsMiddleware = (req: any, res: any, next: any) => {
      const allowedOrigins = ['http://localhost:3000', 'https://trusted-domain.com'];
      const origin = req.headers.origin;
      
      if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
      }
      
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Max-Age', '86400');
      
      if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
      }
      
      next();
    };
    
    // Mock authentication middleware
    const authenticate = (req: any, res: any, next: any) => {
      const token = req.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }
      
      if (token === 'valid-token') {
        req.user = { id: 'user123', role: 'user' };
        next();
      } else if (token === 'admin-token') {
        req.user = { id: 'admin123', role: 'admin' };
        next();
      } else {
        return res.status(401).json({ error: 'Invalid token' });
      }
    };
    
    // Mock authorization middleware
    const authorize = (roles: string[]) => {
      return (req: any, res: any, next: any) => {
        if (!req.user || !roles.includes(req.user.role)) {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
      };
    };
    
    // Security headers middleware
    const securityHeaders = (req: any, res: any, next: any) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Content-Security-Policy', "default-src 'self'");
      next();
    };
    
    app.use(securityHeaders);
    app.use(corsMiddleware);
    
    // Public endpoints
    app.get('/api/v1/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });
    
    app.post('/api/v1/login', (req, res) => {
      const { username, password } = req.body;
      
      if (username === 'admin' && password === 'admin123') {
        res.json({ token: 'admin-token', role: 'admin' });
      } else if (username === 'user' && password === 'user123') {
        res.json({ token: 'valid-token', role: 'user' });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    });
    
    // Protected endpoints
    app.get('/api/v1/profile', authenticate, (req, res) => {
      res.json({ user: req.user });
    });
    
    app.get('/api/v1/users', authenticate, authorize(['admin']), (req, res) => {
      res.json({ users: [{ id: '1', username: 'user1' }] });
    });
    
    // Rate limited endpoint
    app.post('/api/v1/upload', rateLimit(5, 60000), authenticate, (req, res) => {
      res.json({ message: 'File uploaded successfully' });
    });
    
    // Vulnerable endpoint for testing
    app.post('/api/v1/vulnerable/search', (req, res) => {
      const { query } = req.body;
      
      // Intentionally vulnerable for testing
      if (query.includes('DROP TABLE')) {
        res.status(400).json({ error: 'SQL injection detected' });
      } else {
        res.json({ results: [] });
      }
    });
    
    // Parameter pollution test endpoint
    app.get('/api/v1/items', (req, res) => {
      const { category, sort } = req.query;
      
      // Check for parameter pollution
      if (Array.isArray(category) || Array.isArray(sort)) {
        return res.status(400).json({ error: 'Parameter pollution detected' });
      }
      
      res.json({ items: [], category, sort });
    });
    
    // Mass assignment test endpoint
    app.put('/api/v1/user/:id', authenticate, (req, res) => {
      const allowedFields = ['name', 'email'];
      const updates = req.body;
      
      // Check for mass assignment
      const providedFields = Object.keys(updates);
      const unauthorizedFields = providedFields.filter(field => !allowedFields.includes(field));
      
      if (unauthorizedFields.length > 0) {
        return res.status(400).json({ 
          error: 'Mass assignment detected', 
          unauthorizedFields 
        });
      }
      
      res.json({ message: 'User updated successfully', updates });
    });
    
    return app;
  }
  
  static generateMaliciousApiPayloads() {
    return {
      headers: {
        oversized: 'A'.repeat(100000),
        nullByte: 'Authorization\0: Bearer token',
        crlf: 'X-Forwarded-For: evil.com\r\nX-Injected: malicious',
        unicode: 'X-Test: \u0000\u0001\u0002',
        xss: 'X-Custom: <script>alert("xss")</script>'
      },
      
      queryParams: {
        sqlInjection: "'; DROP TABLE users; --",
        xss: '<script>alert("xss")</script>',
        pathTraversal: '../../../etc/passwd',
        overflow: 'A'.repeat(10000),
        pollution: ['value1', 'value2'] // Array for parameter pollution
      },
      
      jsonPayloads: {
        oversized: { data: 'A'.repeat(10000000) }, // 10MB
        prototypePollution: {
          '__proto__': { admin: true },
          'constructor': { 'prototype': { admin: true } }
        },
        xmlBomb: {
          xml: '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>'
        },
        deepNested: this.createDeeplyNestedObject(1000)
      }
    };
  }
  
  static createDeeplyNestedObject(depth: number): any {
    if (depth === 0) return { value: 'deep' };
    return { nested: this.createDeeplyNestedObject(depth - 1) };
  }
  
  static async performRapidRequests(app: any, endpoint: string, count: number, headers: any = {}) {
    const promises = [];
    
    for (let i = 0; i < count; i++) {
      promises.push(
        request(app)
          .post(endpoint)
          .set(headers)
          .send({ data: `request_${i}` })
      );
    }
    
    return Promise.all(promises.map(p => p.catch(err => err)));
  }
}

describe('API Security Test Suite', () => {
  let app: any;
  
  beforeEach(() => {
    app = ApiSecurityTestSuite.createMockApiServer();
    jest.clearAllMocks();
  });
  
  describe('Rate Limiting and DoS Protection', () => {
    test('should enforce rate limits on endpoints', async () => {
      const authHeader = { 'Authorization': 'Bearer valid-token' };
      
      // Make 6 rapid requests (limit is 5)
      const results = await ApiSecurityTestSuite.performRapidRequests(
        app, 
        '/api/v1/upload', 
        6, 
        authHeader
      );
      
      // At least one should be rate limited
      const rateLimitedResponses = results.filter(result => 
        result.status === 429 || (result.response && result.response.status === 429)
      );
      
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
    
    test('should handle oversized request payloads', async () => {
      const { oversized } = ApiSecurityTestSuite.generateMaliciousApiPayloads().jsonPayloads;
      
      const response = await request(app)
        .post('/api/v1/vulnerable/search')
        .send(oversized)
        .expect(413); // Payload too large
    });
    
    test('should prevent request smuggling attacks', async () => {
      const maliciousHeaders = {
        'Content-Length': '10',
        'Transfer-Encoding': 'chunked'
      };
      
      const response = await request(app)
        .post('/api/v1/vulnerable/search')
        .set(maliciousHeaders)
        .send('0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: localhost\r\n\r\n');
      
      // Should not process the smuggled request
      expect(response.status).not.toBe(200);
    });
    
    test('should handle deeply nested JSON objects', async () => {
      const { deepNested } = ApiSecurityTestSuite.generateMaliciousApiPayloads().jsonPayloads;
      
      const response = await request(app)
        .post('/api/v1/vulnerable/search')
        .send({ query: JSON.stringify(deepNested) });
      
      // Should not crash the server
      expect([200, 400, 413]).toContain(response.status);
    });
  });
  
  describe('CORS Policy Enforcement', () => {
    test('should enforce CORS policies correctly', async () => {
      // Test with allowed origin
      const allowedOriginResponse = await request(app)
        .options('/api/v1/profile')
        .set('Origin', 'http://localhost:3000')
        .expect(200);
      
      expect(allowedOriginResponse.headers['access-control-allow-origin'])
        .toBe('http://localhost:3000');
      
      // Test with disallowed origin
      const disallowedOriginResponse = await request(app)
        .options('/api/v1/profile')
        .set('Origin', 'http://evil.com');
      
      expect(disallowedOriginResponse.headers['access-control-allow-origin'])
        .not.toBe('http://evil.com');
    });
    
    test('should handle CORS preflight requests securely', async () => {
      const response = await request(app)
        .options('/api/v1/profile')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'GET')
        .set('Access-Control-Request-Headers', 'Authorization')
        .expect(200);
      
      expect(response.headers['access-control-allow-methods']).toBeDefined();
      expect(response.headers['access-control-allow-headers']).toBeDefined();
      expect(response.headers['access-control-max-age']).toBeDefined();
    });
  });
  
  describe('HTTP Method Security', () => {
    test('should validate HTTP methods', async () => {
      // Test method not allowed
      await request(app)
        .patch('/api/v1/health')
        .expect(404); // Should not be found/allowed
    });
    
    test('should prevent HTTP verb tampering', async () => {
      // Test X-HTTP-Method-Override header
      const response = await request(app)
        .post('/api/v1/users')
        .set('X-HTTP-Method-Override', 'DELETE')
        .set('Authorization', 'Bearer admin-token');
      
      // Should not treat as DELETE request
      expect(response.status).not.toBe(200);
    });
  });
  
  describe('Authorization and Access Control', () => {
    test('should enforce authentication on protected endpoints', async () => {
      // Test without token
      await request(app)
        .get('/api/v1/profile')
        .expect(401);
      
      // Test with invalid token
      await request(app)
        .get('/api/v1/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
      
      // Test with valid token
      await request(app)
        .get('/api/v1/profile')
        .set('Authorization', 'Bearer valid-token')
        .expect(200);
    });
    
    test('should enforce role-based authorization', async () => {
      // Test user accessing admin endpoint
      await request(app)
        .get('/api/v1/users')
        .set('Authorization', 'Bearer valid-token')
        .expect(403);
      
      // Test admin accessing admin endpoint
      await request(app)
        .get('/api/v1/users')
        .set('Authorization', 'Bearer admin-token')
        .expect(200);
    });
    
    test('should prevent privilege escalation', async () => {
      const maliciousPayload = {
        name: 'John Doe',
        email: 'john@example.com',
        role: 'admin', // Attempt to escalate privileges
        isAdmin: true
      };
      
      const response = await request(app)
        .put('/api/v1/user/123')
        .set('Authorization', 'Bearer valid-token')
        .send(maliciousPayload)
        .expect(400);
      
      expect(response.body.error).toContain('Mass assignment detected');
      expect(response.body.unauthorizedFields).toContain('role');
      expect(response.body.unauthorizedFields).toContain('isAdmin');
    });
  });
  
  describe('Request Header Security', () => {
    test('should validate request headers', async () => {
      const { headers } = ApiSecurityTestSuite.generateMaliciousApiPayloads();
      
      // Test oversized header
      const oversizedResponse = await request(app)
        .get('/api/v1/health')
        .set('X-Large-Header', headers.oversized);
      
      // Should handle gracefully
      expect([200, 400, 431]).toContain(oversizedResponse.status);
      
      // Test header injection
      const injectionResponse = await request(app)
        .get('/api/v1/health')
        .set('X-Custom', headers.crlf);
      
      // Should not inject additional headers
      expect(injectionResponse.headers['x-injected']).toBeUndefined();
    });
    
    test('should set secure response headers', async () => {
      const response = await request(app)
        .get('/api/v1/health')
        .expect(200);
      
      // Check security headers are present
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('1; mode=block');
      expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
      expect(response.headers['content-security-policy']).toBe("default-src 'self'");
    });
  });
  
  describe('Parameter Pollution Prevention', () => {
    test('should detect and prevent parameter pollution', async () => {
      // Test with duplicate query parameters
      const response = await request(app)
        .get('/api/v1/items?category=books&category=movies')
        .expect(400);
      
      expect(response.body.error).toContain('Parameter pollution detected');
    });
    
    test('should handle array parameters securely', async () => {
      // Test legitimate array parameter usage
      const response = await request(app)
        .get('/api/v1/items')
        .query({ category: 'books', sort: 'name' })
        .expect(200);
      
      expect(response.body.category).toBe('books');
      expect(response.body.sort).toBe('name');
    });
  });
  
  describe('API Versioning Security', () => {
    test('should validate API version headers', async () => {
      // Test with invalid version
      const response = await request(app)
        .get('/api/v999/health');
      
      expect(response.status).toBe(404);
    });
    
    test('should prevent version enumeration', async () => {
      const versions = ['v0', 'v1', 'v2', 'v3', 'v10', 'v100'];
      
      for (const version of versions) {
        const response = await request(app).get(`/api/${version}/health`);
        
        // Should not reveal information about other versions
        if (response.status === 404) {
          expect(response.text).not.toContain('available versions');
          expect(response.text).not.toContain('v1');
        }
      }
    });
  });
  
  describe('Input Validation at API Level', () => {
    test('should validate JSON input structure', async () => {
      const malformedJson = '{ "name": "test", "invalid": }'; // Malformed JSON
      
      const response = await request(app)
        .post('/api/v1/vulnerable/search')
        .type('json')
        .send(malformedJson)
        .expect(400);
    });
    
    test('should prevent prototype pollution via JSON', async () => {
      const { prototypePollution } = ApiSecurityTestSuite.generateMaliciousApiPayloads().jsonPayloads;
      
      const response = await request(app)
        .post('/api/v1/vulnerable/search')
        .send(prototypePollution);
      
      // Should not pollute Object.prototype
      expect((Object.prototype as any).admin).toBeUndefined();
      expect(response.status).toBeLessThan(500); // Should not cause server error
    });
    
    test('should validate content-type headers', async () => {
      // Test with wrong content-type
      const response = await request(app)
        .post('/api/v1/vulnerable/search')
        .set('Content-Type', 'text/plain')
        .send('{"query": "test"}');
      
      // Should handle content-type mismatch appropriately
      expect([400, 415]).toContain(response.status); // Bad Request or Unsupported Media Type
    });
  });
  
  describe('Error Handling Security', () => {
    test('should not expose sensitive information in error messages', async () => {
      // Test SQL injection error
      const response = await request(app)
        .post('/api/v1/vulnerable/search')
        .send({ query: "'; DROP TABLE users; --" })
        .expect(400);
      
      expect(response.body.error).toBe('SQL injection detected');
      
      // Should not contain sensitive details
      expect(response.body.error).not.toContain('database');
      expect(response.body.error).not.toContain('password');
      expect(response.body.error).not.toContain('connection');
    });
    
    test('should handle internal server errors securely', async () => {
      // Trigger a potential server error
      const response = await request(app)
        .get('/api/v1/nonexistent-endpoint');
      
      // Should not expose stack traces or internal details
      if (response.status >= 500) {
        expect(response.body).not.toHaveProperty('stack');
        expect(response.body).not.toHaveProperty('trace');
        expect(response.text).not.toContain('/home/');
        expect(response.text).not.toContain('node_modules');
      }
    });
    
    test('should implement proper error status codes', async () => {
      const testCases = [
        { endpoint: '/api/v1/nonexistent', expectedStatus: 404 },
        { endpoint: '/api/v1/profile', expectedStatus: 401, headers: {} }, // No auth
        { endpoint: '/api/v1/users', expectedStatus: 403, headers: { 'Authorization': 'Bearer valid-token' } }, // Wrong role
      ];
      
      for (const testCase of testCases) {
        const response = await request(app)
          .get(testCase.endpoint)
          .set(testCase.headers || {});
        
        expect(response.status).toBe(testCase.expectedStatus);
      }
    });
  });
  
  describe('Session and State Management', () => {
    test('should not maintain state between requests', async () => {
      // First request
      const response1 = await request(app)
        .post('/api/v1/login')
        .send({ username: 'admin', password: 'admin123' })
        .expect(200);
      
      const token = response1.body.token;
      
      // Second request - should require explicit authentication
      const response2 = await request(app)
        .get('/api/v1/profile')
        .expect(401); // Should require token
      
      // Third request with token - should work
      const response3 = await request(app)
        .get('/api/v1/profile')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
    });
  });
  
  afterEach(() => {
    jest.restoreAllMocks();
  });
});
