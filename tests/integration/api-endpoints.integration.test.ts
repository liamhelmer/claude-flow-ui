/**
 * API Endpoint Integration Tests
 * Tests API endpoints using supertest for full HTTP request/response testing
 */

import request from 'supertest';
import { createServer } from 'http';
import express, { Express } from 'express';
import cors from 'cors';
import { Server as SocketIOServer } from 'socket.io';
import { ApiClient } from '@/lib/api';

describe('API Endpoints Integration', () => {
  let app: Express;
  let server: any;
  let io: SocketIOServer;
  let apiClient: ApiClient;
  let port: number;

  beforeAll((done) => {
    // Create Express app similar to unified-server.js
    app = express();
    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Create HTTP server
    server = createServer(app);
    io = new SocketIOServer(server, {
      cors: { origin: "*", methods: ["GET", "POST"] },
      path: '/api/ws'
    });

    // Setup test API routes
    setupTestRoutes();

    // Start server on random port
    server.listen(0, () => {
      port = server.address().port;
      apiClient = new ApiClient(`http://localhost:${port}/api`);
      done();
    });
  });

  afterAll((done) => {
    if (io) io.close();
    if (server) server.close(done);
  });

  function setupTestRoutes() {
    // Health check endpoint
    app.get('/api/health', (req, res) => {
      res.json({ status: 'ok', timestamp: Date.now() });
    });

    // Terminal management endpoints
    app.get('/api/terminals', (req, res) => {
      res.json({
        terminals: [
          { id: 'terminal-1', name: 'Main Terminal', status: 'active' },
          { id: 'terminal-2', name: 'Debug Terminal', status: 'inactive' }
        ]
      });
    });

    app.post('/api/terminals', (req, res) => {
      const { name, command } = req.body;

      if (!name) {
        return res.status(400).json({ error: 'Terminal name is required' });
      }

      const newTerminal = {
        id: `terminal-${Date.now()}`,
        name,
        command: command || '/bin/bash',
        status: 'active',
        created: new Date().toISOString()
      };

      res.status(201).json(newTerminal);
    });

    app.get('/api/terminals/:id', (req, res) => {
      const { id } = req.params;

      if (id === 'non-existent') {
        return res.status(404).json({ error: 'Terminal not found' });
      }

      res.json({
        id,
        name: `Terminal ${id}`,
        status: 'active',
        command: '/bin/bash'
      });
    });

    app.delete('/api/terminals/:id', (req, res) => {
      const { id } = req.params;

      if (id === 'non-existent') {
        return res.status(404).json({ error: 'Terminal not found' });
      }

      res.json({ message: 'Terminal deleted successfully' });
    });

    // Session management endpoints
    app.get('/api/sessions', (req, res) => {
      res.json({
        sessions: [
          { id: 'session-1', name: 'Main Session', terminals: ['terminal-1'] },
          { id: 'session-2', name: 'Debug Session', terminals: ['terminal-2'] }
        ]
      });
    });

    app.post('/api/sessions', (req, res) => {
      const { name, config } = req.body;

      const newSession = {
        id: `session-${Date.now()}`,
        name: name || 'New Session',
        config: config || {},
        terminals: [],
        created: new Date().toISOString()
      };

      res.status(201).json(newSession);
    });

    app.put('/api/sessions/:id', (req, res) => {
      const { id } = req.params;
      const { name, config } = req.body;

      res.json({
        id,
        name: name || `Session ${id}`,
        config: config || {},
        updated: new Date().toISOString()
      });
    });

    // Configuration endpoints
    app.get('/api/config', (req, res) => {
      res.json({
        terminal: {
          shell: '/bin/bash',
          cols: 80,
          rows: 24
        },
        server: {
          port: 3000,
          host: 'localhost'
        }
      });
    });

    app.post('/api/config', (req, res) => {
      const { terminal, server } = req.body;

      res.json({
        message: 'Configuration updated',
        config: { terminal, server }
      });
    });

    // Monitoring endpoints
    app.get('/api/monitoring/metrics', (req, res) => {
      res.json({
        cpu: Math.random() * 100,
        memory: Math.random() * 100,
        terminals: Math.floor(Math.random() * 10),
        uptime: Date.now() - 1000000
      });
    });

    app.get('/api/monitoring/logs', (req, res) => {
      const { level, limit } = req.query;

      res.json({
        logs: Array.from({ length: parseInt(limit as string) || 10 }, (_, i) => ({
          timestamp: new Date(Date.now() - i * 1000).toISOString(),
          level: level || 'info',
          message: `Log message ${i}`,
          source: 'server'
        }))
      });
    });

    // File operations endpoints
    app.get('/api/files', (req, res) => {
      const { path } = req.query;

      res.json({
        path: path || '/',
        files: [
          { name: 'file1.txt', type: 'file', size: 1024 },
          { name: 'directory1', type: 'directory', size: 0 },
          { name: 'script.sh', type: 'file', size: 2048, executable: true }
        ]
      });
    });

    app.post('/api/files/execute', (req, res) => {
      const { path, args } = req.body;

      if (!path) {
        return res.status(400).json({ error: 'File path is required' });
      }

      res.json({
        message: 'File executed',
        output: `Executing ${path} with args: ${JSON.stringify(args || [])}`,
        exitCode: 0
      });
    });

    // Error handling endpoints for testing
    app.get('/api/error/500', (req, res) => {
      res.status(500).json({ error: 'Internal server error' });
    });

    app.get('/api/error/timeout', (req, res) => {
      // Simulate timeout - don't respond
      setTimeout(() => {
        res.json({ message: 'This should timeout' });
      }, 30000);
    });

    // Rate limiting test endpoint
    let requestCount = 0;
    app.get('/api/rate-limit-test', (req, res) => {
      requestCount++;
      if (requestCount > 10) {
        return res.status(429).json({ error: 'Too many requests' });
      }
      res.json({ requestCount });
    });
  }

  describe('Health Check Endpoints', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body.status).toBe('ok');
      expect(response.body.timestamp).toBeGreaterThan(0);
    });

    it('should handle health check with ApiClient', async () => {
      const health = await apiClient.get('/health');
      expect(health.status).toBe('ok');
    });
  });

  describe('Terminal Management Endpoints', () => {
    it('should list all terminals', async () => {
      const response = await request(app)
        .get('/api/terminals')
        .expect(200);

      expect(response.body.terminals).toHaveLength(2);
      expect(response.body.terminals[0]).toHaveProperty('id');
      expect(response.body.terminals[0]).toHaveProperty('name');
      expect(response.body.terminals[0]).toHaveProperty('status');
    });

    it('should create a new terminal', async () => {
      const terminalData = {
        name: 'Test Terminal',
        command: '/bin/zsh'
      };

      const response = await request(app)
        .post('/api/terminals')
        .send(terminalData)
        .expect(201);

      expect(response.body.name).toBe(terminalData.name);
      expect(response.body.command).toBe(terminalData.command);
      expect(response.body.id).toMatch(/^terminal-\d+$/);
      expect(response.body.status).toBe('active');
    });

    it('should validate terminal creation data', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .send({}) // Missing name
        .expect(400);

      expect(response.body.error).toBe('Terminal name is required');
    });

    it('should get terminal by ID', async () => {
      const response = await request(app)
        .get('/api/terminals/test-terminal')
        .expect(200);

      expect(response.body.id).toBe('test-terminal');
      expect(response.body.name).toBe('Terminal test-terminal');
    });

    it('should handle non-existent terminal', async () => {
      const response = await request(app)
        .get('/api/terminals/non-existent')
        .expect(404);

      expect(response.body.error).toBe('Terminal not found');
    });

    it('should delete terminal', async () => {
      const response = await request(app)
        .delete('/api/terminals/test-terminal')
        .expect(200);

      expect(response.body.message).toBe('Terminal deleted successfully');
    });

    it('should handle terminal operations with ApiClient', async () => {
      // List terminals
      const terminals = await apiClient.get('/terminals');
      expect(terminals.terminals).toHaveLength(2);

      // Create terminal
      const newTerminal = await apiClient.post('/terminals', {
        name: 'API Client Terminal',
        command: '/bin/bash'
      });
      expect(newTerminal.name).toBe('API Client Terminal');

      // Get specific terminal
      const terminal = await apiClient.get(`/terminals/${newTerminal.id}`);
      expect(terminal.id).toBe(newTerminal.id);
    });
  });

  describe('Session Management Endpoints', () => {
    it('should list all sessions', async () => {
      const response = await request(app)
        .get('/api/sessions')
        .expect(200);

      expect(response.body.sessions).toHaveLength(2);
      expect(response.body.sessions[0]).toHaveProperty('id');
      expect(response.body.sessions[0]).toHaveProperty('name');
      expect(response.body.sessions[0]).toHaveProperty('terminals');
    });

    it('should create a new session', async () => {
      const sessionData = {
        name: 'Integration Test Session',
        config: { theme: 'dark', fontSize: 14 }
      };

      const response = await request(app)
        .post('/api/sessions')
        .send(sessionData)
        .expect(201);

      expect(response.body.name).toBe(sessionData.name);
      expect(response.body.config).toEqual(sessionData.config);
      expect(response.body.id).toMatch(/^session-\d+$/);
    });

    it('should update session configuration', async () => {
      const updateData = {
        name: 'Updated Session',
        config: { theme: 'light' }
      };

      const response = await request(app)
        .put('/api/sessions/test-session')
        .send(updateData)
        .expect(200);

      expect(response.body.name).toBe(updateData.name);
      expect(response.body.config).toEqual(updateData.config);
      expect(response.body.updated).toBeDefined();
    });
  });

  describe('Configuration Endpoints', () => {
    it('should get server configuration', async () => {
      const response = await request(app)
        .get('/api/config')
        .expect(200);

      expect(response.body.terminal).toBeDefined();
      expect(response.body.terminal.shell).toBe('/bin/bash');
      expect(response.body.server).toBeDefined();
    });

    it('should update configuration', async () => {
      const configData = {
        terminal: { shell: '/bin/zsh', cols: 120, rows: 40 },
        server: { port: 8080 }
      };

      const response = await request(app)
        .post('/api/config')
        .send(configData)
        .expect(200);

      expect(response.body.message).toBe('Configuration updated');
      expect(response.body.config).toEqual(configData);
    });
  });

  describe('Monitoring Endpoints', () => {
    it('should get system metrics', async () => {
      const response = await request(app)
        .get('/api/monitoring/metrics')
        .expect(200);

      expect(response.body.cpu).toBeGreaterThanOrEqual(0);
      expect(response.body.memory).toBeGreaterThanOrEqual(0);
      expect(response.body.terminals).toBeGreaterThanOrEqual(0);
      expect(response.body.uptime).toBeGreaterThan(0);
    });

    it('should get logs with filters', async () => {
      const response = await request(app)
        .get('/api/monitoring/logs')
        .query({ level: 'error', limit: 5 })
        .expect(200);

      expect(response.body.logs).toHaveLength(5);
      response.body.logs.forEach((log: any) => {
        expect(log).toHaveProperty('timestamp');
        expect(log).toHaveProperty('level');
        expect(log).toHaveProperty('message');
        expect(log.level).toBe('error');
      });
    });
  });

  describe('File Operations Endpoints', () => {
    it('should list files in directory', async () => {
      const response = await request(app)
        .get('/api/files')
        .query({ path: '/home/user' })
        .expect(200);

      expect(response.body.path).toBe('/home/user');
      expect(response.body.files).toHaveLength(3);
      expect(response.body.files[0]).toHaveProperty('name');
      expect(response.body.files[0]).toHaveProperty('type');
      expect(response.body.files[0]).toHaveProperty('size');
    });

    it('should execute files', async () => {
      const executeData = {
        path: '/home/user/script.sh',
        args: ['--verbose', '--output', '/tmp/result']
      };

      const response = await request(app)
        .post('/api/files/execute')
        .send(executeData)
        .expect(200);

      expect(response.body.message).toBe('File executed');
      expect(response.body.output).toContain('/home/user/script.sh');
      expect(response.body.exitCode).toBe(0);
    });

    it('should validate file execution data', async () => {
      const response = await request(app)
        .post('/api/files/execute')
        .send({}) // Missing path
        .expect(400);

      expect(response.body.error).toBe('File path is required');
    });
  });

  describe('Error Handling', () => {
    it('should handle 500 errors', async () => {
      const response = await request(app)
        .get('/api/error/500')
        .expect(500);

      expect(response.body.error).toBe('Internal server error');
    });

    it('should handle 404 errors', async () => {
      const response = await request(app)
        .get('/api/non-existent-endpoint')
        .expect(404);
    });

    it('should handle ApiClient errors', async () => {
      await expect(apiClient.get('/non-existent-endpoint')).rejects.toThrow('API Error');
    });

    it('should handle malformed JSON', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);
    });
  });

  describe('Request Validation', () => {
    it('should validate Content-Type headers', async () => {
      const response = await request(app)
        .post('/api/terminals')
        .set('Content-Type', 'text/plain')
        .send('not json')
        .expect(400);
    });

    it('should handle large request bodies', async () => {
      const largeData = {
        name: 'Large Terminal',
        config: 'A'.repeat(10000) // 10KB string
      };

      const response = await request(app)
        .post('/api/sessions')
        .send(largeData)
        .expect(201);

      expect(response.body.name).toBe(largeData.name);
    });
  });

  describe('Rate Limiting', () => {
    it('should handle rate limiting', async () => {
      // Make multiple requests to trigger rate limit
      const requests = Array.from({ length: 12 }, () =>
        request(app).get('/api/rate-limit-test')
      );

      const responses = await Promise.all(requests);

      // First 10 should succeed
      responses.slice(0, 10).forEach(response => {
        expect(response.status).toBe(200);
      });

      // Last 2 should be rate limited
      responses.slice(10).forEach(response => {
        expect(response.status).toBe(429);
      });
    });
  });

  describe('Concurrent Requests', () => {
    it('should handle concurrent requests without conflicts', async () => {
      const concurrentRequests = Array.from({ length: 10 }, (_, i) =>
        request(app)
          .post('/api/terminals')
          .send({ name: `Concurrent Terminal ${i}` })
      );

      const responses = await Promise.all(concurrentRequests);

      responses.forEach((response, index) => {
        expect(response.status).toBe(201);
        expect(response.body.name).toBe(`Concurrent Terminal ${index}`);
        expect(response.body.id).toMatch(/^terminal-\d+$/);
      });

      // All terminals should have unique IDs
      const ids = responses.map(r => r.body.id);
      const uniqueIds = [...new Set(ids)];
      expect(uniqueIds).toHaveLength(10);
    });

    it('should maintain data consistency under load', async () => {
      const operations = [
        () => request(app).get('/api/terminals'),
        () => request(app).post('/api/terminals').send({ name: 'Load Test Terminal' }),
        () => request(app).get('/api/sessions'),
        () => request(app).post('/api/sessions').send({ name: 'Load Test Session' }),
        () => request(app).get('/api/monitoring/metrics')
      ];

      // Execute operations concurrently multiple times
      const batches = Array.from({ length: 5 }, () =>
        Promise.all(operations.map(op => op()))
      );

      const batchResults = await Promise.all(batches);

      // All operations should complete successfully
      batchResults.forEach(batch => {
        batch.forEach(response => {
          expect(response.status).toBeLessThan(400);
        });
      });
    });
  });

  describe('Performance Testing', () => {
    it('should respond quickly to simple requests', async () => {
      const startTime = Date.now();

      await request(app)
        .get('/api/health')
        .expect(200);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(responseTime).toBeLessThan(100); // Should respond within 100ms
    });

    it('should handle multiple sequential requests efficiently', async () => {
      const startTime = Date.now();

      for (let i = 0; i < 20; i++) {
        await request(app)
          .get('/api/health')
          .expect(200);
      }

      const endTime = Date.now();
      const totalTime = endTime - startTime;

      expect(totalTime).toBeLessThan(2000); // 20 requests should complete within 2 seconds
    });
  });

  describe('CORS and Security', () => {
    it('should set CORS headers', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.headers['access-control-allow-origin']).toBeDefined();
    });

    it('should handle preflight requests', async () => {
      const response = await request(app)
        .options('/api/terminals')
        .expect(204);

      expect(response.headers['access-control-allow-methods']).toBeDefined();
    });
  });
});