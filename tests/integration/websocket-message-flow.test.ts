/**
 * WebSocket Message Flow Integration Tests
 *
 * These tests validate the complete WebSocket message flow from client to server
 * and back, including session management, authentication, message routing,
 * and real-time data streaming.
 */

import { io, Socket } from 'socket.io-client';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { WebSocketClient } from '../../src/lib/websocket/client';
import { database } from '../../rest-api/src/config/database';
import { redisClient } from '../../rest-api/src/config/redis';
import { User } from '../../rest-api/src/models/User';
import jwt from 'jsonwebtoken';
import { config } from '../../rest-api/src/config/environment';

// Mock terminal session data
interface MockTerminalSession {
  id: string;
  userId: string;
  status: 'active' | 'inactive';
  createdAt: Date;
  lastActivity: Date;
}

describe('WebSocket Message Flow Integration Tests', () => {
  let httpServer: any;
  let socketServer: SocketIOServer;
  let testUser: User;
  let authToken: string;
  let clientSocket: Socket;
  let wsClient: WebSocketClient;
  let serverPort: number;
  let mockSessions: Map<string, MockTerminalSession> = new Map();

  const testUserData = {
    firstName: 'WebSocket',
    lastName: 'Tester',
    email: 'websocket.tester@test.com',
    password: 'hashedpassword123',
    role: 'user' as const,
  };

  beforeAll(async () => {
    // Initialize database
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_ws_test';
    process.env.JWT_SECRET = 'test-jwt-secret';

    await database.connect();
    await database.sync({ force: true });
    await redisClient.connect();

    // Create test user
    testUser = await User.create(testUserData);
    authToken = jwt.sign(
      { userId: testUser.id, email: testUser.email },
      config.jwt.secret,
      { expiresIn: '1h' }
    );

    // Set up mock WebSocket server
    httpServer = createServer();
    socketServer = new SocketIOServer(httpServer, {
      path: '/api/ws',
      cors: {
        origin: true,
        credentials: true,
      },
      transports: ['websocket', 'polling'],
    });

    // Start server on random port
    await new Promise<void>((resolve) => {
      httpServer.listen(0, () => {
        serverPort = httpServer.address().port;
        console.log(`Test WebSocket server running on port ${serverPort}`);
        resolve();
      });
    });

    // Set up server-side message handlers
    setupServerHandlers();
  }, 30000);

  afterAll(async () => {
    // Clean up
    await User.destroy({ where: {} });
    await database.disconnect();
    await redisClient.flushall();
    await redisClient.disconnect();
    
    if (clientSocket) {
      clientSocket.disconnect();
    }
    if (wsClient) {
      wsClient.disconnect();
    }
    
    socketServer.close();
    httpServer.close();
  }, 30000);

  beforeEach(async () => {
    // Clear Redis and reset mock data
    await redisClient.flushall();
    mockSessions.clear();
  });

  function setupServerHandlers() {
    socketServer.on('connection', (socket) => {
      console.log(`Client connected: ${socket.id}`);

      // Authentication handler
      socket.on('authenticate', async (data) => {
        try {
          const { token } = data;
          const decoded = jwt.verify(token, config.jwt.secret) as any;
          
          socket.data.userId = decoded.userId;
          socket.data.authenticated = true;
          
          socket.emit('authenticated', {
            success: true,
            userId: decoded.userId,
          });
        } catch (error) {
          socket.emit('auth_error', {
            error: 'Authentication failed',
            message: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      });

      // Terminal session creation
      socket.on('create-session', async (data) => {
        if (!socket.data.authenticated) {
          socket.emit('session-error', { error: 'Not authenticated' });
          return;
        }

        const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const session: MockTerminalSession = {
          id: sessionId,
          userId: socket.data.userId,
          status: 'active',
          createdAt: new Date(),
          lastActivity: new Date(),
        };

        mockSessions.set(sessionId, session);
        
        // Store in Redis for persistence
        await redisClient.setex(
          `session:${sessionId}`,
          3600,
          JSON.stringify(session)
        );

        socket.join(`session:${sessionId}`);
        socket.emit('session-created', {
          sessionId,
          status: 'active',
          createdAt: session.createdAt,
        });
      });

      // Terminal data streaming
      socket.on('terminal-input', async (data) => {
        const { sessionId, input, timestamp } = data;
        
        // Validate session ownership
        const session = mockSessions.get(sessionId);
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('terminal-error', {
            sessionId,
            error: 'Invalid session or access denied',
          });
          return;
        }

        // Update last activity
        session.lastActivity = new Date();
        await redisClient.setex(
          `session:${sessionId}`,
          3600,
          JSON.stringify(session)
        );

        // Simulate terminal processing and response
        const processedInput = input.trim();
        let output = '';

        if (processedInput === 'ls') {
          output = 'file1.txt  file2.txt  directory1/\n';
        } else if (processedInput === 'pwd') {
          output = '/home/user\n';
        } else if (processedInput.startsWith('echo ')) {
          output = processedInput.substring(5) + '\n';
        } else if (processedInput === 'clear') {
          output = '\x1b[2J\x1b[H'; // ANSI clear screen
        } else {
          output = `bash: ${processedInput}: command not found\n`;
        }

        // Emit terminal output back to client
        socket.emit('terminal-data', {
          sessionId,
          data: output,
          timestamp: Date.now(),
        });
      });

      // Terminal resize handler
      socket.on('terminal-resize', async (data) => {
        const { sessionId, cols, rows } = data;
        
        const session = mockSessions.get(sessionId);
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('terminal-error', {
            sessionId,
            error: 'Invalid session or access denied',
          });
          return;
        }

        // Store resize info in Redis
        await redisClient.setex(
          `session:${sessionId}:size`,
          3600,
          JSON.stringify({ cols, rows })
        );

        socket.emit('terminal-resize', {
          sessionId,
          cols,
          rows,
          success: true,
        });
      });

      // Session destruction
      socket.on('destroy-session', async (data) => {
        const { sessionId } = data;
        
        const session = mockSessions.get(sessionId);
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('session-error', {
            error: 'Invalid session or access denied',
          });
          return;
        }

        // Clean up session
        mockSessions.delete(sessionId);
        await redisClient.del(`session:${sessionId}`);
        await redisClient.del(`session:${sessionId}:size`);
        
        socket.leave(`session:${sessionId}`);
        socket.emit('session-destroyed', {
          sessionId,
          timestamp: Date.now(),
        });
      });

      socket.on('disconnect', (reason) => {
        console.log(`Client disconnected: ${socket.id}, reason: ${reason}`);
      });
    });
  }

  describe('WebSocket Connection Flow', () => {
    test('should establish WebSocket connection successfully', async () => {
      clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Connection timeout'));
        }, 5000);

        clientSocket.on('connect', () => {
          clearTimeout(timeout);
          expect(clientSocket.connected).toBe(true);
          expect(clientSocket.id).toBeTruthy();
          resolve();
        });

        clientSocket.on('connect_error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });
    });

    test('should handle authentication flow', async () => {
      if (!clientSocket?.connected) {
        await new Promise<void>((resolve) => {
          clientSocket = io(`http://localhost:${serverPort}`, {
            path: '/api/ws',
            transports: ['websocket'],
            forceNew: true,
          });
          clientSocket.on('connect', resolve);
        });
      }

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Authentication timeout'));
        }, 5000);

        clientSocket.on('authenticated', (data) => {
          clearTimeout(timeout);
          expect(data.success).toBe(true);
          expect(data.userId).toBe(testUser.id);
          resolve();
        });

        clientSocket.on('auth_error', (error) => {
          clearTimeout(timeout);
          reject(new Error(`Authentication failed: ${error.error}`));
        });

        clientSocket.emit('authenticate', { token: authToken });
      });
    });

    test('should reject invalid authentication token', async () => {
      const invalidSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Test timeout'));
        }, 5000);

        invalidSocket.on('connect', () => {
          invalidSocket.emit('authenticate', { token: 'invalid-token' });
        });

        invalidSocket.on('auth_error', (error) => {
          clearTimeout(timeout);
          expect(error.error).toBe('Authentication failed');
          invalidSocket.disconnect();
          resolve();
        });

        invalidSocket.on('authenticated', () => {
          clearTimeout(timeout);
          invalidSocket.disconnect();
          reject(new Error('Should not authenticate with invalid token'));
        });
      });
    });
  });

  describe('Terminal Session Management Flow', () => {
    beforeEach(async () => {
      if (!clientSocket?.connected) {
        clientSocket = io(`http://localhost:${serverPort}`, {
          path: '/api/ws',
          transports: ['websocket'],
          forceNew: true,
        });
        await new Promise<void>((resolve) => {
          clientSocket.on('connect', resolve);
        });
      }

      // Authenticate
      await new Promise<void>((resolve, reject) => {
        clientSocket.on('authenticated', () => resolve());
        clientSocket.on('auth_error', (error) => reject(error));
        clientSocket.emit('authenticate', { token: authToken });
      });
    });

    test('should create terminal session and store in Redis', async () => {
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Session creation timeout'));
        }, 5000);

        clientSocket.on('session-created', async (data) => {
          clearTimeout(timeout);
          
          expect(data.sessionId).toBeTruthy();
          expect(data.status).toBe('active');
          expect(data.createdAt).toBeTruthy();

          // Verify session was stored in Redis
          const redisSession = await redisClient.get(`session:${data.sessionId}`);
          expect(redisSession).toBeTruthy();
          
          const sessionData = JSON.parse(redisSession!);
          expect(sessionData.userId).toBe(testUser.id);
          expect(sessionData.status).toBe('active');
          
          resolve();
        });

        clientSocket.emit('create-session', {});
      });
    });

    test('should handle terminal input/output flow', async () => {
      let sessionId: string;

      // Create session first
      await new Promise<void>((resolve) => {
        clientSocket.on('session-created', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-session', {});
      });

      // Test command execution flow
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Terminal I/O timeout'));
        }, 5000);

        clientSocket.on('terminal-data', (data) => {
          clearTimeout(timeout);
          
          expect(data.sessionId).toBe(sessionId);
          expect(data.data).toBe('/home/user\n');
          expect(data.timestamp).toBeTruthy();
          
          resolve();
        });

        clientSocket.emit('terminal-input', {
          sessionId,
          input: 'pwd',
          timestamp: Date.now(),
        });
      });
    });

    test('should handle terminal resize events', async () => {
      let sessionId: string;

      // Create session
      await new Promise<void>((resolve) => {
        clientSocket.on('session-created', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-session', {});
      });

      // Test resize handling
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Resize timeout'));
        }, 5000);

        clientSocket.on('terminal-resize', async (data) => {
          clearTimeout(timeout);
          
          expect(data.sessionId).toBe(sessionId);
          expect(data.cols).toBe(120);
          expect(data.rows).toBe(30);
          expect(data.success).toBe(true);

          // Verify size was stored in Redis
          const sizeData = await redisClient.get(`session:${sessionId}:size`);
          expect(sizeData).toBeTruthy();
          
          const size = JSON.parse(sizeData!);
          expect(size.cols).toBe(120);
          expect(size.rows).toBe(30);
          
          resolve();
        });

        clientSocket.emit('terminal-resize', {
          sessionId,
          cols: 120,
          rows: 30,
        });
      });
    });

    test('should destroy session and clean up Redis data', async () => {
      let sessionId: string;

      // Create session
      await new Promise<void>((resolve) => {
        clientSocket.on('session-created', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-session', {});
      });

      // Verify session exists in Redis
      let redisSession = await redisClient.get(`session:${sessionId}`);
      expect(redisSession).toBeTruthy();

      // Destroy session
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Session destruction timeout'));
        }, 5000);

        clientSocket.on('session-destroyed', async (data) => {
          clearTimeout(timeout);
          
          expect(data.sessionId).toBe(sessionId);
          expect(data.timestamp).toBeTruthy();

          // Verify session was removed from Redis
          const deletedSession = await redisClient.get(`session:${sessionId}`);
          expect(deletedSession).toBeNull();
          
          resolve();
        });

        clientSocket.emit('destroy-session', { sessionId });
      });
    });
  });

  describe('WebSocket Client Integration', () => {
    test('should integrate with custom WebSocket client class', async () => {
      wsClient = new WebSocketClient(`http://localhost:${serverPort}`);
      
      // Test connection
      await wsClient.connect();
      expect(wsClient.connected).toBe(true);
      
      // Test event handling
      const receivedMessages: any[] = [];
      wsClient.on('terminal-data', (data) => {
        receivedMessages.push(data);
      });
      
      // Simulate server sending data
      socketServer.emit('terminal-data', {
        sessionId: 'test-session',
        data: 'test output',
        timestamp: Date.now(),
      });
      
      // Allow time for message processing
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(receivedMessages).toHaveLength(1);
      expect(receivedMessages[0]).toMatchObject({
        sessionId: 'test-session',
        data: 'test output',
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(async () => {
      if (!clientSocket?.connected) {
        clientSocket = io(`http://localhost:${serverPort}`, {
          path: '/api/ws',
          transports: ['websocket'],
          forceNew: true,
        });
        await new Promise<void>((resolve) => {
          clientSocket.on('connect', resolve);
        });
        await new Promise<void>((resolve) => {
          clientSocket.on('authenticated', () => resolve());
          clientSocket.emit('authenticate', { token: authToken });
        });
      }
    });

    test('should reject unauthorized session access', async () => {
      // Create session with one user
      let sessionId: string;
      await new Promise<void>((resolve) => {
        clientSocket.on('session-created', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-session', {});
      });

      // Try to access with different user token
      const otherUserToken = jwt.sign(
        { userId: 'different-user-id', email: 'other@test.com' },
        config.jwt.secret,
        { expiresIn: '1h' }
      );

      const unauthorizedSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Test timeout'));
        }, 5000);

        unauthorizedSocket.on('connect', () => {
          unauthorizedSocket.emit('authenticate', { token: otherUserToken });
        });

        unauthorizedSocket.on('authenticated', () => {
          // Try to access the session
          unauthorizedSocket.emit('terminal-input', {
            sessionId,
            input: 'ls',
            timestamp: Date.now(),
          });
        });

        unauthorizedSocket.on('terminal-error', (error) => {
          clearTimeout(timeout);
          expect(error.error).toContain('access denied');
          unauthorizedSocket.disconnect();
          resolve();
        });
      });
    });

    test('should handle connection drops and reconnection', async () => {
      // Force disconnect
      clientSocket.disconnect();
      
      // Verify disconnection
      expect(clientSocket.connected).toBe(false);
      
      // Reconnect
      clientSocket.connect();
      
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Reconnection timeout'));
        }, 5000);

        clientSocket.on('connect', () => {
          clearTimeout(timeout);
          expect(clientSocket.connected).toBe(true);
          resolve();
        });
      });
    });

    test('should handle malformed messages gracefully', async () => {
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Error handling timeout'));
        }, 5000);

        // Listen for any error responses
        clientSocket.on('terminal-error', (error) => {
          clearTimeout(timeout);
          expect(error.error).toBeTruthy();
          resolve();
        });

        clientSocket.on('session-error', (error) => {
          clearTimeout(timeout);
          expect(error.error).toBeTruthy();
          resolve();
        });

        // Send malformed data
        clientSocket.emit('terminal-input', {
          // Missing sessionId
          input: 'test command',
        });
      });
    });
  });

  describe('Performance and Load Testing', () => {
    test('should handle rapid message bursts', async () => {
      let sessionId: string;

      // Create session
      await new Promise<void>((resolve) => {
        clientSocket.on('session-created', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-session', {});
      });

      const messageCount = 50;
      const receivedMessages: any[] = [];
      
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error(`Only received ${receivedMessages.length}/${messageCount} messages`));
        }, 10000);

        clientSocket.on('terminal-data', (data) => {
          receivedMessages.push(data);
          
          if (receivedMessages.length === messageCount) {
            clearTimeout(timeout);
            
            // Verify all messages were received in order
            for (let i = 0; i < messageCount; i++) {
              expect(receivedMessages[i].data).toBe(`echo test message ${i}\n`);
            }
            
            resolve();
          }
        });

        // Send rapid burst of messages
        for (let i = 0; i < messageCount; i++) {
          clientSocket.emit('terminal-input', {
            sessionId,
            input: `echo test message ${i}`,
            timestamp: Date.now() + i,
          });
        }
      });
    });

    test('should handle large message payloads', async () => {
      let sessionId: string;

      await new Promise<void>((resolve) => {
        clientSocket.on('session-created', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-session', {});
      });

      const largeMessage = 'A'.repeat(10000); // 10KB message
      
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Large message timeout'));
        }, 5000);

        clientSocket.on('terminal-data', (data) => {
          clearTimeout(timeout);
          expect(data.data).toBe(largeMessage + '\n');
          resolve();
        });

        clientSocket.emit('terminal-input', {
          sessionId,
          input: `echo ${largeMessage}`,
          timestamp: Date.now(),
        });
      });
    });
  });
});
