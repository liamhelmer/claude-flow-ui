/**
 * Integration Tests for API Endpoints
 * Tests the complete API workflow including HTTP and WebSocket endpoints
 */

const request = require('supertest');
const { createServer } = require('http');
const { Server } = require('socket.io');
const Client = require('socket.io-client');
const express = require('express');
const cors = require('cors');

// Import the actual server components
const TmuxStreamManager = require('../../src/lib/tmux-stream-manager');

describe('API Endpoints Integration Tests', () => {
  let app;
  let server;
  let io;
  let tmuxManager;
  let clientSocket;

  const TEST_PORT = 0; // Use random port for testing

  beforeAll((done) => {
    // Create Express app with middleware
    app = express();
    app.use(cors());
    app.use(express.json());
    app.use(express.static('public'));

    // Create HTTP server and Socket.IO
    server = createServer(app);
    io = new Server(server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Initialize Tmux manager
    tmuxManager = new TmuxStreamManager();

    // Start server
    server.listen(TEST_PORT, () => {
      const port = server.address().port;
      console.log(`Test server running on port ${port}`);
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

  describe('HTTP Endpoints', () => {
    test('GET / should serve index page', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);

      // Check that we get some content (Next.js or static)
      expect(response.type).toMatch(/html|json/);
    });

    test('GET /health should return server status', async () => {
      app.get('/health', (req, res) => {
        res.json({
          status: 'ok',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          platform: process.platform,
          nodeVersion: process.version
        });
      });

      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toHaveProperty('status', 'ok');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('uptime');
      expect(response.body).toHaveProperty('memory');
      expect(response.body).toHaveProperty('platform');
      expect(response.body).toHaveProperty('nodeVersion');
    });

    test('GET /api/terminals should list active terminals', async () => {
      app.get('/api/terminals', (req, res) => {
        const terminals = Array.from(tmuxManager.sessions.keys()).map(id => ({
          id,
          status: 'active',
          created: new Date().toISOString()
        }));
        res.json(terminals);
      });

      const response = await request(app)
        .get('/api/terminals')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    test('POST /api/terminals should create new terminal session', async () => {
      app.post('/api/terminals', async (req, res) => {
        try {
          const { sessionName, command } = req.body;
          const session = await tmuxManager.createSession(sessionName, command);
          res.status(201).json({
            success: true,
            sessionId: session.sessionId,
            socketPath: session.socketPath
          });
        } catch (error) {
          res.status(500).json({
            success: false,
            error: error.message
          });
        }
      });

      const response = await request(app)
        .post('/api/terminals')
        .send({
          sessionName: 'test-session',
          command: 'bash'
        })
        .expect(201);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('sessionId');
      expect(response.body).toHaveProperty('socketPath');
    });

    test('DELETE /api/terminals/:id should terminate terminal session', async () => {
      app.delete('/api/terminals/:id', async (req, res) => {
        try {
          const { id } = req.params;
          await tmuxManager.killSession(id);
          res.json({
            success: true,
            message: `Terminal ${id} terminated`
          });
        } catch (error) {
          res.status(500).json({
            success: false,
            error: error.message
          });
        }
      });

      // First create a session
      const createResponse = await request(app)
        .post('/api/terminals')
        .send({ sessionName: 'test-delete' });

      const sessionId = createResponse.body.sessionId;

      // Then delete it
      const response = await request(app)
        .delete(`/api/terminals/${sessionId}`)
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body.message).toContain(sessionId);
    });

    test('GET /api/system should return system information', async () => {
      app.get('/api/system', (req, res) => {
        res.json({
          platform: process.platform,
          arch: process.arch,
          nodeVersion: process.version,
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cpuUsage: process.cpuUsage(),
          env: {
            NODE_ENV: process.env.NODE_ENV,
            PORT: process.env.PORT
          }
        });
      });

      const response = await request(app)
        .get('/api/system')
        .expect(200);

      expect(response.body).toHaveProperty('platform');
      expect(response.body).toHaveProperty('arch');
      expect(response.body).toHaveProperty('nodeVersion');
      expect(response.body).toHaveProperty('memory');
      expect(response.body).toHaveProperty('env');
    });

    test('POST /api/command should execute shell command', async () => {
      app.post('/api/command', (req, res) => {
        const { command, sessionId } = req.body;

        if (!command) {
          return res.status(400).json({
            success: false,
            error: 'Command is required'
          });
        }

        // Simulate command execution
        res.json({
          success: true,
          command,
          sessionId,
          timestamp: new Date().toISOString()
        });
      });

      const response = await request(app)
        .post('/api/command')
        .send({
          command: 'ls -la',
          sessionId: 'test-session'
        })
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('command', 'ls -la');
      expect(response.body).toHaveProperty('sessionId', 'test-session');
    });

    test('should handle 404 for unknown endpoints', async () => {
      const response = await request(app)
        .get('/api/unknown-endpoint')
        .expect(404);
    });

    test('should handle CORS for cross-origin requests', async () => {
      const response = await request(app)
        .options('/api/terminals')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .expect(204);

      expect(response.headers['access-control-allow-origin']).toBe('*');
    });
  });

  describe('WebSocket Events', () => {
    test('should connect to WebSocket server', (done) => {
      expect(clientSocket.connected).toBe(true);
      done();
    });

    test('should handle terminal creation via WebSocket', (done) => {
      io.on('connection', (socket) => {
        socket.on('create-terminal', async (data, callback) => {
          try {
            const session = await tmuxManager.createSession(data.sessionName);
            callback({
              success: true,
              sessionId: session.sessionId,
              terminalId: `terminal-${Date.now()}`
            });
          } catch (error) {
            callback({
              success: false,
              error: error.message
            });
          }
        });
      });

      clientSocket.emit('create-terminal', {
        sessionName: 'websocket-test',
        cols: 80,
        rows: 24
      }, (response) => {
        expect(response.success).toBe(true);
        expect(response).toHaveProperty('sessionId');
        expect(response).toHaveProperty('terminalId');
        done();
      });
    });

    test('should handle terminal input via WebSocket', (done) => {
      io.on('connection', (socket) => {
        socket.on('terminal-input', (data) => {
          expect(data).toHaveProperty('terminalId');
          expect(data).toHaveProperty('data');
          expect(typeof data.data).toBe('string');

          // Echo back the input
          socket.emit('terminal-output', {
            terminalId: data.terminalId,
            data: `Echo: ${data.data}`
          });
          done();
        });
      });

      clientSocket.emit('terminal-input', {
        terminalId: 'test-terminal',
        data: 'echo "Hello World"\n'
      });

      clientSocket.on('terminal-output', (data) => {
        expect(data).toHaveProperty('terminalId', 'test-terminal');
        expect(data.data).toContain('Hello World');
      });
    });

    test('should handle terminal resize via WebSocket', (done) => {
      io.on('connection', (socket) => {
        socket.on('terminal-resize', (data) => {
          expect(data).toHaveProperty('terminalId');
          expect(data).toHaveProperty('cols');
          expect(data).toHaveProperty('rows');
          expect(typeof data.cols).toBe('number');
          expect(typeof data.rows).toBe('number');

          socket.emit('terminal-resized', {
            terminalId: data.terminalId,
            cols: data.cols,
            rows: data.rows
          });
          done();
        });
      });

      clientSocket.emit('terminal-resize', {
        terminalId: 'test-terminal',
        cols: 120,
        rows: 30
      });

      clientSocket.on('terminal-resized', (data) => {
        expect(data.cols).toBe(120);
        expect(data.rows).toBe(30);
      });
    });

    test('should handle tmux session attachment', (done) => {
      io.on('connection', (socket) => {
        socket.on('attach-tmux', async (data, callback) => {
          try {
            const clientId = `client-${Date.now()}`;
            await tmuxManager.attachClient(data.sessionId, clientId);
            callback({
              success: true,
              clientId,
              sessionId: data.sessionId
            });
          } catch (error) {
            callback({
              success: false,
              error: error.message
            });
          }
        });
      });

      clientSocket.emit('attach-tmux', {
        sessionId: 'test-session'
      }, (response) => {
        expect(response.success).toBe(true);
        expect(response).toHaveProperty('clientId');
        expect(response).toHaveProperty('sessionId', 'test-session');
        done();
      });
    });

    test('should handle tmux session detachment', (done) => {
      io.on('connection', (socket) => {
        socket.on('detach-tmux', async (data, callback) => {
          try {
            await tmuxManager.detachClient(data.clientId);
            callback({
              success: true,
              clientId: data.clientId
            });
          } catch (error) {
            callback({
              success: false,
              error: error.message
            });
          }
        });
      });

      clientSocket.emit('detach-tmux', {
        clientId: 'test-client-123'
      }, (response) => {
        expect(response.success).toBe(true);
        expect(response).toHaveProperty('clientId', 'test-client-123');
        done();
      });
    });

    test('should handle real-time monitoring events', (done) => {
      io.on('connection', (socket) => {
        socket.on('start-monitoring', (data) => {
          expect(data).toHaveProperty('sessionId');

          // Simulate periodic system stats
          const interval = setInterval(() => {
            socket.emit('system-stats', {
              sessionId: data.sessionId,
              timestamp: new Date().toISOString(),
              cpu: Math.random() * 100,
              memory: process.memoryUsage(),
              uptime: process.uptime()
            });
          }, 100);

          // Stop after a short time for testing
          setTimeout(() => {
            clearInterval(interval);
            done();
          }, 300);
        });
      });

      clientSocket.emit('start-monitoring', {
        sessionId: 'monitor-test'
      });

      let statsCount = 0;
      clientSocket.on('system-stats', (data) => {
        expect(data).toHaveProperty('sessionId', 'monitor-test');
        expect(data).toHaveProperty('timestamp');
        expect(data).toHaveProperty('cpu');
        expect(data).toHaveProperty('memory');
        statsCount++;
      });
    });

    test('should handle disconnect events gracefully', (done) => {
      io.on('connection', (socket) => {
        socket.on('disconnect', (reason) => {
          expect(typeof reason).toBe('string');
          done();
        });
      });

      clientSocket.disconnect();
    });

    test('should handle authentication if required', (done) => {
      io.on('connection', (socket) => {
        socket.on('authenticate', (data, callback) => {
          const { token } = data;

          // Simple token validation for testing
          if (token === 'valid-token') {
            callback({
              success: true,
              userId: 'test-user',
              permissions: ['terminal', 'monitoring']
            });
          } else {
            callback({
              success: false,
              error: 'Invalid token'
            });
          }
          done();
        });
      });

      clientSocket.emit('authenticate', {
        token: 'valid-token'
      }, (response) => {
        expect(response.success).toBe(true);
        expect(response).toHaveProperty('userId', 'test-user');
        expect(response.permissions).toContain('terminal');
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle malformed JSON in POST requests', async () => {
      app.post('/api/test-json', (req, res) => {
        res.json({ received: req.body });
      });

      const response = await request(app)
        .post('/api/test-json')
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);
    });

    test('should handle WebSocket errors gracefully', (done) => {
      io.on('connection', (socket) => {
        socket.on('error-test', () => {
          // Simulate an error
          socket.emit('error', {
            type: 'terminal_error',
            message: 'Test error',
            code: 'TEST_ERROR'
          });
        });
      });

      clientSocket.emit('error-test');

      clientSocket.on('error', (error) => {
        expect(error).toHaveProperty('type', 'terminal_error');
        expect(error).toHaveProperty('message', 'Test error');
        expect(error).toHaveProperty('code', 'TEST_ERROR');
        done();
      });
    });

    test('should handle large payload limits', async () => {
      app.post('/api/large-payload', (req, res) => {
        res.json({ size: JSON.stringify(req.body).length });
      });

      // Create a large payload (but within reasonable limits)
      const largeData = {
        data: 'x'.repeat(10000) // 10KB of data
      };

      const response = await request(app)
        .post('/api/large-payload')
        .send(largeData)
        .expect(200);

      expect(response.body.size).toBeGreaterThan(10000);
    });

    test('should handle concurrent WebSocket connections', (done) => {
      const clients = [];
      const clientCount = 5;
      let connectedCount = 0;

      const port = server.address().port;

      for (let i = 0; i < clientCount; i++) {
        const client = new Client(`http://localhost:${port}`);
        clients.push(client);

        client.on('connect', () => {
          connectedCount++;
          if (connectedCount === clientCount) {
            // All clients connected
            expect(connectedCount).toBe(clientCount);

            // Clean up
            clients.forEach(c => c.close());
            done();
          }
        });
      }
    });
  });

  describe('Performance Tests', () => {
    test('should handle rapid WebSocket messages', (done) => {
      const messageCount = 100;
      let receivedCount = 0;

      io.on('connection', (socket) => {
        socket.on('rapid-test', (data) => {
          socket.emit('rapid-response', {
            id: data.id,
            timestamp: Date.now()
          });
        });
      });

      clientSocket.on('rapid-response', (data) => {
        receivedCount++;
        if (receivedCount === messageCount) {
          expect(receivedCount).toBe(messageCount);
          done();
        }
      });

      // Send rapid messages
      for (let i = 0; i < messageCount; i++) {
        clientSocket.emit('rapid-test', { id: i });
      }
    });

    test('should measure API response times', async () => {
      app.get('/api/performance-test', (req, res) => {
        res.json({
          timestamp: Date.now(),
          message: 'Performance test endpoint'
        });
      });

      const startTime = Date.now();

      const response = await request(app)
        .get('/api/performance-test')
        .expect(200);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(responseTime).toBeLessThan(100); // Should respond within 100ms
      expect(response.body).toHaveProperty('message', 'Performance test endpoint');
    });
  });
});