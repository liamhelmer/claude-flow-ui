/**
 * API Client and WebSocket Client Integration Tests
 *
 * These tests validate the integration between frontend clients and backend services,
 * testing real network communication, error handling, retry logic, and data flow
 * between client components and API/WebSocket endpoints.
 */

import { ApiClient } from '../../src/lib/api/index';
import { WebSocketClient } from '../../src/lib/websocket/client';
import { createServer } from 'http';
import express, { Application } from 'express';
import { Server as SocketIOServer } from 'socket.io';
import { io, Socket } from 'socket.io-client';
import jwt from 'jsonwebtoken';

describe('API Client and WebSocket Client Integration Tests', () => {
  let httpServer: any;
  let expressApp: Application;
  let socketServer: SocketIOServer;
  let serverPort: number;
  let apiClient: ApiClient;
  let wsClient: WebSocketClient;
  let testToken: string;

  // Mock API data
  const mockUsers = [
    { id: '1', name: 'John Doe', email: 'john@test.com' },
    { id: '2', name: 'Jane Smith', email: 'jane@test.com' },
  ];

  const mockSessions = new Map<string, any>();

  beforeAll(async () => {
    // Set up Express server with API endpoints
    expressApp = express();
    expressApp.use(express.json());

    // Mock authentication middleware
    const authMiddleware = (req: any, res: any, next: any) => {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
      }
      
      const token = authHeader.substring(7);
      try {
        const decoded = jwt.verify(token, 'test-secret') as any;
        req.user = decoded;
        next();
      } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    };

    // API endpoints for testing
    expressApp.get('/api/health', (req, res) => {
      res.json({ status: 'ok', timestamp: Date.now() });
    });

    expressApp.get('/api/users', (req, res) => {
      res.json({ success: true, users: mockUsers });
    });

    expressApp.get('/api/users/:id', (req, res) => {
      const user = mockUsers.find(u => u.id === req.params.id);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ success: true, user });
    });

    expressApp.post('/api/users', (req, res) => {
      const newUser = {
        id: String(mockUsers.length + 1),
        ...req.body,
      };
      mockUsers.push(newUser);
      res.status(201).json({ success: true, user: newUser });
    });

    expressApp.delete('/api/users/:id', authMiddleware, (req, res) => {
      const index = mockUsers.findIndex(u => u.id === req.params.id);
      if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
      }
      mockUsers.splice(index, 1);
      res.json({ success: true, message: 'User deleted' });
    });

    // Error simulation endpoints
    expressApp.get('/api/error/500', (req, res) => {
      res.status(500).json({ error: 'Internal server error' });
    });

    expressApp.get('/api/error/timeout', (req, res) => {
      // Don't send response to simulate timeout
      setTimeout(() => {
        res.json({ delayed: true });
      }, 10000); // 10 second delay
    });

    expressApp.get('/api/error/network', (req, res) => {
      // Simulate network error by closing connection
      req.socket.destroy();
    });

    // Start HTTP server
    httpServer = createServer(expressApp);
    
    // Set up WebSocket server
    socketServer = new SocketIOServer(httpServer, {
      path: '/api/ws',
      cors: { origin: true, credentials: true },
    });

    setupWebSocketHandlers();

    await new Promise<void>((resolve) => {
      httpServer.listen(0, () => {
        serverPort = httpServer.address().port;
        console.log(`Test server running on port ${serverPort}`);
        resolve();
      });
    });

    // Initialize clients
    apiClient = new ApiClient(`http://localhost:${serverPort}/api`);
    wsClient = new WebSocketClient(`http://localhost:${serverPort}`);

    // Generate test token
    testToken = jwt.sign(
      { userId: 'test-user', email: 'test@example.com' },
      'test-secret',
      { expiresIn: '1h' }
    );
  }, 30000);

  afterAll(async () => {
    if (wsClient) {
      wsClient.disconnect();
    }
    if (socketServer) {
      socketServer.close();
    }
    if (httpServer) {
      httpServer.close();
    }
  }, 30000);

  beforeEach(() => {
    // Reset mock data
    mockSessions.clear();
  });

  function setupWebSocketHandlers() {
    socketServer.on('connection', (socket) => {
      console.log(`WebSocket client connected: ${socket.id}`);

      socket.on('authenticate', (data) => {
        try {
          const { token } = data;
          const decoded = jwt.verify(token, 'test-secret') as any;
          socket.data.user = decoded;
          socket.emit('authenticated', { success: true, userId: decoded.userId });
        } catch (error) {
          socket.emit('auth_error', { error: 'Authentication failed' });
        }
      });

      socket.on('create-session', (data) => {
        if (!socket.data.user) {
          socket.emit('error', { message: 'Not authenticated' });
          return;
        }

        const sessionId = `session_${Date.now()}`;
        const session = {
          id: sessionId,
          userId: socket.data.user.userId,
          createdAt: new Date(),
          ...data,
        };

        mockSessions.set(sessionId, session);
        socket.emit('session-created', session);
      });

      socket.on('terminal-input', (data) => {
        const { sessionId, input } = data;
        const session = mockSessions.get(sessionId);
        
        if (!session || session.userId !== socket.data.user?.userId) {
          socket.emit('error', { message: 'Invalid session' });
          return;
        }

        // Echo input back as output
        socket.emit('terminal-data', {
          sessionId,
          data: `Echo: ${input}\n`,
          timestamp: Date.now(),
        });
      });

      socket.on('ping', (data) => {
        socket.emit('pong', { ...data, timestamp: Date.now() });
      });

      socket.on('disconnect', (reason) => {
        console.log(`WebSocket client disconnected: ${socket.id}, reason: ${reason}`);
      });
    });
  }

  describe('API Client Integration', () => {
    describe('Basic HTTP Operations', () => {
      test('should successfully make GET request', async () => {
        const response = await apiClient.get('/health');
        
        expect(response).toMatchObject({
          status: 'ok',
          timestamp: expect.any(Number),
        });
      });

      test('should successfully make POST request', async () => {
        const newUser = {
          name: 'Test User',
          email: 'test.user@example.com',
        };

        const response = await apiClient.post('/users', newUser);
        
        expect(response).toMatchObject({
          success: true,
          user: {
            id: expect.any(String),
            name: newUser.name,
            email: newUser.email,
          },
        });
      });

      test('should successfully make DELETE request with authentication', async () => {
        // Override API client to include auth header
        const authApiClient = new ApiClient(`http://localhost:${serverPort}/api`);
        
        // Mock the fetch to include auth header
        const originalFetch = global.fetch;
        global.fetch = jest.fn().mockImplementation((url, options = {}) => {
          const authOptions = {
            ...options,
            headers: {
              ...options.headers,
              'Authorization': `Bearer ${testToken}`,
            },
          };
          return originalFetch(url, authOptions);
        }) as any;

        try {
          const response = await authApiClient.delete('/users/1');
          
          expect(response).toMatchObject({
            success: true,
            message: 'User deleted',
          });
        } finally {
          global.fetch = originalFetch;
        }
      });

      test('should handle different base URL configurations', async () => {
        // Test with trailing slash
        const clientWithTrailingSlash = new ApiClient(`http://localhost:${serverPort}/api/`);
        const response1 = await clientWithTrailingSlash.get('/health');
        expect(response1.status).toBe('ok');

        // Test with no trailing slash
        const clientWithoutTrailingSlash = new ApiClient(`http://localhost:${serverPort}/api`);
        const response2 = await clientWithoutTrailingSlash.get('/health');
        expect(response2.status).toBe('ok');

        // Test with relative URL in browser environment
        const originalWindow = global.window;
        global.window = { location: { origin: `http://localhost:${serverPort}` } } as any;
        
        try {
          const relativeBrowserClient = new ApiClient();
          const response3 = await relativeBrowserClient.get('/health');
          expect(response3.status).toBe('ok');
        } finally {
          global.window = originalWindow;
        }
      });
    });

    describe('Error Handling', () => {
      test('should handle 404 errors', async () => {
        await expect(apiClient.get('/nonexistent')).rejects.toThrow(
          expect.objectContaining({
            message: expect.stringContaining('404'),
          })
        );
      });

      test('should handle 500 server errors', async () => {
        await expect(apiClient.get('/error/500')).rejects.toThrow(
          expect.objectContaining({
            message: expect.stringContaining('Internal Server Error'),
          })
        );
      });

      test('should handle network errors', async () => {
        await expect(apiClient.get('/error/network')).rejects.toThrow();
      });

      test('should handle malformed JSON responses', async () => {
        // Mock fetch to return invalid JSON
        const originalFetch = global.fetch;
        global.fetch = jest.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: () => Promise.reject(new Error('Invalid JSON')),
        }) as any;

        try {
          await expect(apiClient.get('/health')).rejects.toThrow('Invalid JSON');
        } finally {
          global.fetch = originalFetch;
        }
      });

      test('should validate input parameters', async () => {
        // Test empty endpoint
        await expect(apiClient.get('')).rejects.toThrow(
          'endpoint cannot be empty'
        );

        await expect(apiClient.get('   ')).rejects.toThrow(
          'endpoint cannot be empty'
        );

        // Test invalid endpoint types
        await expect(apiClient.get(null as any)).rejects.toThrow(
          'endpoint must be a non-empty string'
        );

        await expect(apiClient.get(123 as any)).rejects.toThrow(
          'endpoint must be a non-empty string'
        );
      });
    });

    describe('Performance and Reliability', () => {
      test('should handle concurrent requests', async () => {
        const requests = Array(10).fill(null).map((_, i) => 
          apiClient.get(`/users/${i % 2 + 1}`)
        );

        const responses = await Promise.all(requests);
        
        expect(responses).toHaveLength(10);
        responses.forEach((response, i) => {
          expect(response.success).toBe(true);
          expect(response.user.id).toBe(String((i % 2) + 1));
        });
      });

      test('should handle large response payloads', async () => {
        // Mock large response
        const originalFetch = global.fetch;
        const largeData = { data: 'A'.repeat(1000000) }; // 1MB of data
        
        global.fetch = jest.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: () => Promise.resolve(largeData),
        }) as any;

        try {
          const response = await apiClient.get('/large-data');
          expect(response.data).toBe(largeData.data);
        } finally {
          global.fetch = originalFetch;
        }
      });
    });
  });

  describe('WebSocket Client Integration', () => {
    describe('Connection Management', () => {
      test('should establish WebSocket connection', async () => {
        await wsClient.connect();
        expect(wsClient.connected).toBe(true);
      });

      test('should handle authentication flow', async () => {
        if (!wsClient.connected) {
          await wsClient.connect();
        }

        return new Promise<void>((resolve, reject) => {
          wsClient.on('authenticated', (data) => {
            expect(data.success).toBe(true);
            expect(data.userId).toBe('test-user');
            resolve();
          });

          wsClient.on('auth_error', (error) => {
            reject(new Error(error.error));
          });

          wsClient.send('authenticate', { token: testToken });

          setTimeout(() => reject(new Error('Authentication timeout')), 5000);
        });
      });

      test('should handle reconnection after disconnect', async () => {
        if (!wsClient.connected) {
          await wsClient.connect();
        }

        expect(wsClient.connected).toBe(true);
        
        // Force disconnect
        wsClient.disconnect();
        expect(wsClient.connected).toBe(false);
        
        // Reconnect
        await wsClient.connect();
        expect(wsClient.connected).toBe(true);
      });
    });

    describe('Message Flow', () => {
      beforeEach(async () => {
        if (!wsClient.connected) {
          await wsClient.connect();
        }
        
        // Authenticate
        await new Promise<void>((resolve, reject) => {
          wsClient.on('authenticated', () => resolve());
          wsClient.on('auth_error', (error) => reject(error));
          wsClient.send('authenticate', { token: testToken });
        });
      });

      test('should create session and receive confirmation', async () => {
        return new Promise<void>((resolve, reject) => {
          wsClient.on('session-created', (session) => {
            expect(session).toMatchObject({
              id: expect.stringMatching(/^session_\d+$/),
              userId: 'test-user',
              createdAt: expect.any(String),
            });
            resolve();
          });

          wsClient.send('create-session', { name: 'Test Session' });

          setTimeout(() => reject(new Error('Session creation timeout')), 5000);
        });
      });

      test('should handle terminal input/output flow', async () => {
        // Create session first
        let sessionId: string;
        await new Promise<void>((resolve) => {
          wsClient.on('session-created', (session) => {
            sessionId = session.id;
            resolve();
          });
          wsClient.send('create-session', { name: 'Terminal Test' });
        });

        // Test terminal I/O
        return new Promise<void>((resolve, reject) => {
          wsClient.on('terminal-data', (data) => {
            expect(data).toMatchObject({
              sessionId,
              data: 'Echo: test command\n',
              timestamp: expect.any(Number),
            });
            resolve();
          });

          wsClient.send('terminal-input', {
            sessionId,
            input: 'test command',
          });

          setTimeout(() => reject(new Error('Terminal I/O timeout')), 5000);
        });
      });

      test('should handle ping/pong for connection health', async () => {
        const pingData = { id: 'test-ping', timestamp: Date.now() };
        
        return new Promise<void>((resolve, reject) => {
          wsClient.on('pong', (data) => {
            expect(data).toMatchObject({
              id: pingData.id,
              timestamp: expect.any(Number),
            });
            expect(data.timestamp).toBeGreaterThan(pingData.timestamp);
            resolve();
          });

          wsClient.send('ping', pingData);

          setTimeout(() => reject(new Error('Ping/pong timeout')), 5000);
        });
      });
    });

    describe('Event Handling', () => {
      test('should support multiple event listeners', async () => {
        if (!wsClient.connected) {
          await wsClient.connect();
        }

        const listener1Results: any[] = [];
        const listener2Results: any[] = [];
        
        wsClient.on('test-event', (data) => {
          listener1Results.push({ ...data, listener: 1 });
        });
        
        wsClient.on('test-event', (data) => {
          listener2Results.push({ ...data, listener: 2 });
        });

        // Simulate server sending event
        const testData = { message: 'test event data' };
        socketServer.emit('test-event', testData);

        // Allow time for event processing
        await new Promise(resolve => setTimeout(resolve, 100));

        expect(listener1Results).toHaveLength(1);
        expect(listener2Results).toHaveLength(1);
        expect(listener1Results[0]).toMatchObject({ ...testData, listener: 1 });
        expect(listener2Results[0]).toMatchObject({ ...testData, listener: 2 });
      });

      test('should remove event listeners', async () => {
        if (!wsClient.connected) {
          await wsClient.connect();
        }

        const results: any[] = [];
        const listener = (data: any) => {
          results.push(data);
        };
        
        wsClient.on('remove-test', listener);
        
        // Emit event - should be received
        socketServer.emit('remove-test', { test: 1 });
        await new Promise(resolve => setTimeout(resolve, 50));
        
        expect(results).toHaveLength(1);
        
        // Remove listener
        wsClient.off('remove-test', listener);
        
        // Emit event again - should not be received
        socketServer.emit('remove-test', { test: 2 });
        await new Promise(resolve => setTimeout(resolve, 50));
        
        expect(results).toHaveLength(1); // Still only 1
      });
    });

    describe('Error Handling and Edge Cases', () => {
      test('should handle connection failures gracefully', async () => {
        // Create client with invalid URL
        const invalidClient = new WebSocketClient('http://localhost:99999');
        
        await expect(invalidClient.connect()).rejects.toThrow();
        expect(invalidClient.connected).toBe(false);
      });

      test('should handle sending messages when disconnected', async () => {
        if (wsClient.connected) {
          wsClient.disconnect();
        }
        
        expect(wsClient.connected).toBe(false);
        
        // Should not throw error, but should handle gracefully
        expect(() => {
          wsClient.send('test-event', { data: 'test' });
        }).not.toThrow();
      });

      test('should handle malformed messages', async () => {
        if (!wsClient.connected) {
          await wsClient.connect();
        }

        // Test sending malformed data
        expect(() => {
          wsClient.send('test', undefined);
          wsClient.send('test', null);
          wsClient.send('', { data: 'empty event name' });
        }).not.toThrow();
      });

      test('should handle server-side errors', async () => {
        if (!wsClient.connected) {
          await wsClient.connect();
        }

        return new Promise<void>((resolve, reject) => {
          wsClient.on('error', (error) => {
            expect(error.message).toBe('Not authenticated');
            resolve();
          });

          // Send request without authentication
          wsClient.send('create-session', { name: 'Unauthorized' });

          setTimeout(() => reject(new Error('Error handling timeout')), 5000);
        });
      });
    });
  });

  describe('Client Coordination and Integration', () => {
    test('should coordinate between HTTP and WebSocket clients', async () => {
      // Create user via HTTP API
      const newUser = {
        name: 'Coordinated User',
        email: 'coordinated@test.com',
      };

      const httpResponse = await apiClient.post('/users', newUser);
      expect(httpResponse.success).toBe(true);

      // Use user ID in WebSocket session
      if (!wsClient.connected) {
        await wsClient.connect();
      }

      // Authenticate WebSocket
      await new Promise<void>((resolve) => {
        wsClient.on('authenticated', () => resolve());
        wsClient.send('authenticate', { token: testToken });
      });

      // Create session with user context
      const sessionData = await new Promise<any>((resolve) => {
        wsClient.on('session-created', (session) => {
          resolve(session);
        });
        wsClient.send('create-session', {
          userId: httpResponse.user.id,
          name: 'Coordinated Session',
        });
      });

      expect(sessionData).toMatchObject({
        userId: 'test-user', // From JWT token
        id: expect.any(String),
      });
    });

    test('should handle authentication errors consistently', async () => {
      const invalidToken = 'invalid.jwt.token';
      
      // Test HTTP client with invalid token
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockImplementation((url, options = {}) => {
        const authOptions = {
          ...options,
          headers: {
            ...options.headers,
            'Authorization': `Bearer ${invalidToken}`,
          },
        };
        return originalFetch(url, authOptions);
      }) as any;

      try {
        await expect(apiClient.delete('/users/1')).rejects.toThrow(
          expect.objectContaining({
            message: expect.stringContaining('401'),
          })
        );
      } finally {
        global.fetch = originalFetch;
      }

      // Test WebSocket client with invalid token
      if (!wsClient.connected) {
        await wsClient.connect();
      }

      await new Promise<void>((resolve) => {
        wsClient.on('auth_error', (error) => {
          expect(error.error).toBe('Authentication failed');
          resolve();
        });
        wsClient.send('authenticate', { token: invalidToken });
      });
    });

    test('should handle concurrent operations across both clients', async () => {
      // Ensure WebSocket is connected and authenticated
      if (!wsClient.connected) {
        await wsClient.connect();
      }
      
      await new Promise<void>((resolve) => {
        wsClient.on('authenticated', () => resolve());
        wsClient.send('authenticate', { token: testToken });
      });

      // Perform concurrent HTTP and WebSocket operations
      const httpPromises = [
        apiClient.get('/users'),
        apiClient.get('/health'),
      ];

      const wsPromises = [
        new Promise((resolve) => {
          wsClient.on('session-created', resolve);
          wsClient.send('create-session', { name: 'Concurrent 1' });
        }),
        new Promise((resolve) => {
          wsClient.on('pong', resolve);
          wsClient.send('ping', { id: 'concurrent-ping' });
        }),
      ];

      const [httpResults, wsResults] = await Promise.all([
        Promise.all(httpPromises),
        Promise.all(wsPromises),
      ]);

      expect(httpResults).toHaveLength(2);
      expect(wsResults).toHaveLength(2);
      
      // Verify HTTP results
      expect(httpResults[0]).toHaveProperty('users');
      expect(httpResults[1]).toHaveProperty('status', 'ok');
      
      // Verify WebSocket results
      expect(wsResults[0]).toHaveProperty('id');
      expect(wsResults[1]).toHaveProperty('id', 'concurrent-ping');
    });
  });
});
