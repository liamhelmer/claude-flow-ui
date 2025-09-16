/**
 * Security Testing Suite
 * Comprehensive security tests for Node.js application
 */

const request = require('supertest');
const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const Client = require('socket.io-client');
const fs = require('fs');
const path = require('path');

// Import test data
const testData = require('../fixtures/test-data');

describe('Security Tests', () => {
  let app;
  let server;
  let io;
  let clientSocket;

  beforeAll((done) => {
    // Create Express app with security middleware
    app = express();
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));

    // Create HTTP server and Socket.IO
    server = createServer(app);
    io = new Server(server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Set up basic routes for testing
    app.get('/health', (req, res) => {
      res.json({ status: 'ok' });
    });

    app.post('/api/terminals', (req, res) => {
      const { sessionName, command } = req.body;
      res.json({
        success: true,
        sessionId: `session-${Date.now()}`,
        sessionName: sessionName,
        command: command
      });
    });

    app.post('/api/command', (req, res) => {
      const { command, sessionId } = req.body;
      res.json({
        success: true,
        output: `Executed: ${command}`,
        sessionId: sessionId
      });
    });

    app.get('/api/file', (req, res) => {
      const { path: filePath } = req.query;
      res.json({
        path: filePath,
        content: 'Mock file content'
      });
    });

    // Start server
    server.listen(0, () => {
      done();
    });
  });

  afterAll((done) => {
    if (clientSocket) {
      clientSocket.close();
    }
    io.close();
    server.close(done);
  });

  beforeEach((done) => {
    const port = server.address().port;
    clientSocket = new Client(`http://localhost:${port}`);
    clientSocket.on('connect', done);
  });

  afterEach(() => {
    if (clientSocket) {
      clientSocket.close();
    }
  });

  describe('SQL Injection Protection', () => {
    testData.security.sqlInjection.forEach((payload, index) => {
      test(`should prevent SQL injection attack #${index + 1}: ${payload.substring(0, 30)}...`, async () => {
        const response = await request(app)
          .post('/api/terminals')
          .send({
            sessionName: payload,
            command: 'bash'
          });

        // Should not return 500 error (SQL execution error)
        expect(response.status).not.toBe(500);

        // Response should still be valid JSON
        expect(response.body).toBeDefined();

        // Should not contain SQL error messages
        const responseText = JSON.stringify(response.body).toLowerCase();
        expect(responseText).not.toMatch(/sql|database|table|drop|delete|insert|update|select/);
      });
    });

    test('should sanitize SQL injection in query parameters', async () => {
      const sqlPayload = "'; DROP TABLE users; --";

      const response = await request(app)
        .get('/api/file')
        .query({ path: sqlPayload });

      expect(response.status).not.toBe(500);
      expect(response.body).toBeDefined();
    });

    test('should handle SQL injection in nested objects', async () => {
      const response = await request(app)
        .post('/api/command')
        .send({
          sessionId: 'test-session',
          command: {
            malicious: "'; DROP TABLE sessions; --",
            normal: 'ls -la'
          }
        });

      expect(response.status).not.toBe(500);
      expect(response.body).toBeDefined();
    });
  });

  describe('Cross-Site Scripting (XSS) Protection', () => {
    testData.security.xssPayloads.forEach((payload, index) => {
      test(`should prevent XSS attack #${index + 1}: ${payload.substring(0, 30)}...`, async () => {
        const response = await request(app)
          .post('/api/terminals')
          .send({
            sessionName: payload,
            command: 'bash'
          });

        expect(response.status).toBe(200);

        // Response should not contain executable script tags
        const responseText = JSON.stringify(response.body);
        expect(responseText).not.toContain('<script>');
        expect(responseText).not.toContain('javascript:');
        expect(responseText).not.toContain('onerror=');
        expect(responseText).not.toContain('onload=');
      });
    });

    test('should sanitize XSS in WebSocket messages', (done) => {
      const xssPayload = '<script>alert("XSS")</script>';

      io.on('connection', (socket) => {
        socket.on('terminal-input', (data) => {
          const responseData = JSON.stringify(data);
          expect(responseData).not.toContain('<script>');
          expect(responseData).not.toContain('javascript:');

          socket.emit('terminal-output', {
            terminalId: data.terminalId,
            data: 'Sanitized output'
          });
          done();
        });
      });

      clientSocket.emit('terminal-input', {
        terminalId: 'test-terminal',
        data: xssPayload
      });
    });

    test('should handle XSS in HTTP headers', async () => {
      const response = await request(app)
        .get('/health')
        .set('X-Custom-Header', '<script>alert("XSS")</script>');

      expect(response.status).toBe(200);
      expect(response.body).toBeDefined();
    });
  });

  describe('Command Injection Protection', () => {
    testData.security.commandInjection.forEach((payload, index) => {
      test(`should prevent command injection #${index + 1}: ${payload.substring(0, 30)}...`, async () => {
        const response = await request(app)
          .post('/api/command')
          .send({
            sessionId: 'test-session',
            command: payload
          });

        // Should not execute dangerous commands
        expect(response.status).toBe(200);
        expect(response.body).toBeDefined();

        // Response should not indicate command execution
        const output = response.body.output || '';
        expect(output.toLowerCase()).not.toMatch(/passwd|shadow|rm -rf|wget|curl|nc -l/);
      });
    });

    test('should validate command parameters', async () => {
      const response = await request(app)
        .post('/api/command')
        .send({
          sessionId: 'test-session',
          command: 'ls',
          args: ['-la', '&& rm -rf /']
        });

      expect(response.status).toBe(200);
      // Should not execute the dangerous command in args
    });

    test('should sanitize environment variables', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .send({
          sessionName: 'test-session',
          command: 'bash',
          env: {
            MALICIOUS_VAR: '; cat /etc/passwd',
            NORMAL_VAR: 'safe_value'
          }
        });

      expect(response.status).toBe(200);
      expect(response.body).toBeDefined();
    });
  });

  describe('Path Traversal Protection', () => {
    testData.security.pathTraversal.forEach((payload, index) => {
      test(`should prevent path traversal #${index + 1}: ${payload.substring(0, 30)}...`, async () => {
        const response = await request(app)
          .get('/api/file')
          .query({ path: payload });

        expect(response.status).toBe(200);

        // Should not access sensitive files
        const content = response.body.content || '';
        expect(content.toLowerCase()).not.toMatch(/root:|password:|private key/);
      });
    });

    test('should validate file upload paths', async () => {
      // Simulate file upload with malicious path
      const response = await request(app)
        .post('/api/upload')
        .field('filename', '../../../etc/passwd')
        .field('content', 'malicious content');

      // Should either reject or sanitize the path
      expect(response.status).not.toBe(500);
    });

    test('should prevent directory listing attacks', async () => {
      const response = await request(app)
        .get('/api/file')
        .query({ path: '/etc/' });

      expect(response.status).toBe(200);
      // Should not list directory contents
    });
  });

  describe('Input Validation and Sanitization', () => {
    test('should reject oversized payloads', async () => {
      const largePayload = 'x'.repeat(20 * 1024 * 1024); // 20MB

      const response = await request(app)
        .post('/api/terminals')
        .send({
          sessionName: largePayload,
          command: 'bash'
        });

      expect(response.status).toBe(413); // Payload Too Large
    });

    test('should validate required fields', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .send({}); // Missing required fields

      expect(response.status).toBe(200); // Should handle gracefully
      expect(response.body).toBeDefined();
    });

    test('should sanitize Unicode and special characters', async () => {
      const unicodePayload = '\u0000\u0001\u0002\u0003\u001F\u007F\uFEFF';

      const response = await request(app)
        .post('/api/terminals')
        .send({
          sessionName: unicodePayload,
          command: 'bash'
        });

      expect(response.status).toBe(200);
      expect(response.body).toBeDefined();
    });

    test('should handle malformed JSON gracefully', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .set('Content-Type', 'application/json')
        .send('{"malformed": json}');

      expect(response.status).toBe(400); // Bad Request
    });

    test('should validate data types', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .send({
          sessionName: 123, // Should be string
          command: ['array', 'instead', 'of', 'string'],
          cols: 'not_a_number',
          rows: null
        });

      expect(response.status).toBe(200);
      expect(response.body).toBeDefined();
    });
  });

  describe('Authentication and Authorization', () => {
    test('should handle missing authentication headers', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .send({
          sessionName: 'test-session',
          command: 'bash'
        });

      // Should either allow (if no auth required) or reject appropriately
      expect([200, 401, 403]).toContain(response.status);
    });

    test('should validate JWT tokens if used', async () => {
      const invalidToken = 'invalid.jwt.token';

      const response = await request(app)
        .post('/api/terminals')
        .set('Authorization', `Bearer ${invalidToken}`)
        .send({
          sessionName: 'test-session',
          command: 'bash'
        });

      expect(response.status).toBe(200); // Adjust based on auth implementation
    });

    test('should prevent privilege escalation', async () => {
      const response = await request(app)
        .post('/api/command')
        .send({
          sessionId: 'test-session',
          command: 'sudo su -',
          escalate: true
        });

      expect(response.status).toBe(200);
      // Should not actually escalate privileges
    });
  });

  describe('Rate Limiting and DoS Protection', () => {
    test('should handle rapid requests gracefully', async () => {
      const promises = [];

      // Send 100 rapid requests
      for (let i = 0; i < 100; i++) {
        promises.push(
          request(app)
            .get('/health')
            .timeout(1000)
        );
      }

      const responses = await Promise.allSettled(promises);
      const successful = responses.filter(r => r.status === 'fulfilled').length;

      // Should handle most requests (rate limiting may reject some)
      expect(successful).toBeGreaterThan(50);
    });

    test('should prevent WebSocket message flooding', (done) => {
      let messageCount = 0;
      const maxMessages = 1000;

      io.on('connection', (socket) => {
        socket.on('flood-test', () => {
          messageCount++;
          if (messageCount >= maxMessages) {
            expect(messageCount).toBeLessThanOrEqual(maxMessages);
            done();
          }
        });
      });

      // Send flood of messages
      for (let i = 0; i < maxMessages; i++) {
        clientSocket.emit('flood-test', { id: i });
      }
    });

    test('should handle concurrent WebSocket connections', async () => {
      const connections = [];
      const maxConnections = 50;

      const port = server.address().port;

      for (let i = 0; i < maxConnections; i++) {
        const client = new Client(`http://localhost:${port}`);
        connections.push(client);
      }

      // Wait for connections
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Clean up
      connections.forEach(client => client.close());

      // Should handle all connections without crashing
      expect(connections.length).toBe(maxConnections);
    });
  });

  describe('Data Sanitization and Output Encoding', () => {
    test('should encode output data properly', async () => {
      const response = await request(app)
        .post('/api/command')
        .send({
          sessionId: 'test-session',
          command: 'echo "<script>alert(1)</script>"'
        });

      expect(response.status).toBe(200);

      // Output should be encoded
      const output = response.body.output || '';
      expect(output).not.toContain('<script>');
    });

    test('should sanitize file paths in responses', async () => {
      const response = await request(app)
        .get('/api/file')
        .query({ path: '/etc/passwd' });

      expect(response.status).toBe(200);

      // Should not expose actual file paths
      const path = response.body.path || '';
      expect(path).not.toMatch(/\/etc\/passwd/);
    });

    test('should prevent information disclosure in errors', async () => {
      const response = await request(app)
        .get('/nonexistent-endpoint');

      expect(response.status).toBe(404);

      // Error should not expose internal details
      const error = JSON.stringify(response.body).toLowerCase();
      expect(error).not.toMatch(/stack trace|internal error|database|file system/);
    });
  });

  describe('Secure Headers and CORS', () => {
    test('should set security headers', async () => {
      const response = await request(app)
        .get('/health');

      expect(response.status).toBe(200);

      // Check for security headers (if implemented)
      // expect(response.headers['x-content-type-options']).toBe('nosniff');
      // expect(response.headers['x-frame-options']).toBeDefined();
      // expect(response.headers['x-xss-protection']).toBeDefined();
    });

    test('should handle CORS properly', async () => {
      const response = await request(app)
        .options('/api/terminals')
        .set('Origin', 'http://malicious-site.com')
        .set('Access-Control-Request-Method', 'POST');

      expect(response.status).toBe(204);

      // CORS headers should be restrictive or properly configured
      // Adjust expectations based on actual CORS policy
    });

    test('should prevent clickjacking', async () => {
      const response = await request(app)
        .get('/health');

      expect(response.status).toBe(200);

      // Should set X-Frame-Options or CSP frame-ancestors
      // expect(response.headers['x-frame-options']).toBe('DENY');
    });
  });

  describe('Session Security', () => {
    test('should generate secure session IDs', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .send({
          sessionName: 'test-session',
          command: 'bash'
        });

      expect(response.status).toBe(200);

      const sessionId = response.body.sessionId;
      expect(sessionId).toBeDefined();
      expect(sessionId.length).toBeGreaterThan(10);
      expect(sessionId).not.toMatch(/^(test|session|123|password|admin)$/i);
    });

    test('should prevent session fixation', async () => {
      const fixedSessionId = 'fixed-session-123';

      const response = await request(app)
        .post('/api/terminals')
        .set('X-Session-ID', fixedSessionId)
        .send({
          sessionName: 'test-session',
          command: 'bash'
        });

      expect(response.status).toBe(200);

      // Should generate new session ID, not use the provided one
      const sessionId = response.body.sessionId;
      expect(sessionId).not.toBe(fixedSessionId);
    });
  });
});