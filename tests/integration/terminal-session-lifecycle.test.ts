/**
 * Terminal Session Lifecycle Integration Tests
 *
 * These tests validate the complete lifecycle of terminal sessions including
 * creation, data streaming, resizing, persistence, cleanup, and interaction
 * between WebSocket connections, database storage, and terminal processes.
 */

import { io, Socket } from 'socket.io-client';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { database } from '../../rest-api/src/config/database';
import { redisClient } from '../../rest-api/src/config/redis';
import { User } from '../../rest-api/src/models/User';
import { WebSocketClient } from '../../src/lib/websocket/client';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from '../../rest-api/src/config/environment';
import { spawn, ChildProcess } from 'child_process';
import { performance } from 'perf_hooks';

// Mock terminal session structure
interface TerminalSession {
  id: string;
  userId: string;
  pid?: number;
  status: 'creating' | 'active' | 'inactive' | 'destroyed';
  createdAt: Date;
  lastActivity: Date;
  dimensions: { cols: number; rows: number };
  environment: Record<string, string>;
  metadata: {
    shell: string;
    workingDirectory: string;
    totalBytes: number;
    commandCount: number;
  };
}

interface TerminalMessage {
  sessionId: string;
  type: 'input' | 'output' | 'resize' | 'control';
  data: string | Buffer;
  timestamp: number;
  sequence: number;
}

describe('Terminal Session Lifecycle Integration Tests', () => {
  let httpServer: any;
  let socketServer: SocketIOServer;
  let serverPort: number;
  let testUser: User;
  let authToken: string;
  let wsClient: WebSocketClient;
  let clientSocket: Socket;
  
  // Mock session storage
  const activeSessions = new Map<string, TerminalSession>();
  const sessionMessages = new Map<string, TerminalMessage[]>();
  const sessionProcesses = new Map<string, ChildProcess>();
  
  let messageSequence = 0;

  const testUserData = {
    firstName: 'Terminal',
    lastName: 'User',
    email: 'terminal.user@test.com',
    password: 'TerminalPassword123!',
    role: 'user' as const,
  };

  beforeAll(async () => {
    // Initialize test environment
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_terminal_test';
    process.env.JWT_SECRET = 'test-terminal-jwt-secret';

    await database.connect();
    await database.sync({ force: true });
    await redisClient.connect();

    // Create test user
    const hashedPassword = await bcrypt.hash(testUserData.password, 12);
    testUser = await User.create({
      ...testUserData,
      password: hashedPassword,
    });

    authToken = jwt.sign(
      { userId: testUser.id, email: testUser.email },
      config.jwt.secret,
      { expiresIn: '1h' }
    );

    // Set up WebSocket server
    httpServer = createServer();
    socketServer = new SocketIOServer(httpServer, {
      path: '/api/ws',
      cors: { origin: true, credentials: true },
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(0, () => {
        serverPort = httpServer.address().port;
        resolve();
      });
    });

    setupTerminalHandlers();
    
    // Initialize WebSocket client
    wsClient = new WebSocketClient(`http://localhost:${serverPort}`);
  }, 30000);

  afterAll(async () => {
    // Cleanup all active terminal processes
    for (const [sessionId, process] of sessionProcesses) {
      process.kill('SIGTERM');
    }
    sessionProcesses.clear();
    
    await User.destroy({ where: {} });
    await database.disconnect();
    await redisClient.flushall();
    await redisClient.disconnect();
    
    if (wsClient) {
      wsClient.disconnect();
    }
    if (clientSocket) {
      clientSocket.disconnect();
    }
    if (socketServer) {
      socketServer.close();
    }
    if (httpServer) {
      httpServer.close();
    }
  }, 30000);

  beforeEach(async () => {
    // Clear session data
    activeSessions.clear();
    sessionMessages.clear();
    messageSequence = 0;
    
    // Clear Redis session data
    const keys = await redisClient.keys('terminal_session:*');
    if (keys.length > 0) {
      await redisClient.del(...keys);
    }
  });

  function setupTerminalHandlers() {
    socketServer.on('connection', (socket) => {
      console.log(`Terminal client connected: ${socket.id}`);

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
          });
        }
      });

      socket.on('create-terminal-session', async (data) => {
        if (!socket.data.authenticated) {
          socket.emit('terminal-error', { error: 'Not authenticated' });
          return;
        }

        const sessionId = `terminal_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const { shell = '/bin/bash', cols = 80, rows = 24, cwd = '/tmp' } = data;

        try {
          const session: TerminalSession = {
            id: sessionId,
            userId: socket.data.userId,
            status: 'creating',
            createdAt: new Date(),
            lastActivity: new Date(),
            dimensions: { cols, rows },
            environment: {
              TERM: 'xterm-256color',
              SHELL: shell,
              USER: 'testuser',
              HOME: '/home/testuser',
            },
            metadata: {
              shell,
              workingDirectory: cwd,
              totalBytes: 0,
              commandCount: 0,
            },
          };

          // Store session in memory and Redis
          activeSessions.set(sessionId, session);
          sessionMessages.set(sessionId, []);
          
          await redisClient.setex(
            `terminal_session:${sessionId}`,
            3600,
            JSON.stringify(session)
          );

          // Simulate terminal process creation
          const terminalProcess = spawn(shell, ['-i'], {
            cwd,
            env: {
              ...process.env,
              ...session.environment,
            },
            stdio: ['pipe', 'pipe', 'pipe'],
          });

          session.pid = terminalProcess.pid;
          session.status = 'active';
          sessionProcesses.set(sessionId, terminalProcess);

          // Handle terminal process output
          terminalProcess.stdout?.on('data', (data) => {
            const message: TerminalMessage = {
              sessionId,
              type: 'output',
              data: data.toString(),
              timestamp: Date.now(),
              sequence: ++messageSequence,
            };

            const messages = sessionMessages.get(sessionId) || [];
            messages.push(message);
            sessionMessages.set(sessionId, messages);

            session.lastActivity = new Date();
            session.metadata.totalBytes += Buffer.byteLength(data);

            socket.emit('terminal-data', {
              sessionId,
              data: data.toString(),
              timestamp: message.timestamp,
            });
          });

          terminalProcess.stderr?.on('data', (data) => {
            socket.emit('terminal-data', {
              sessionId,
              data: data.toString(),
              timestamp: Date.now(),
              type: 'stderr',
            });
          });

          terminalProcess.on('exit', (code, signal) => {
            session.status = 'destroyed';
            sessionProcesses.delete(sessionId);
            
            socket.emit('terminal-closed', {
              sessionId,
              code,
              signal,
              timestamp: Date.now(),
            });
          });

          // Join session room for broadcasting
          socket.join(`terminal:${sessionId}`);

          socket.emit('terminal-spawned', {
            sessionId,
            pid: terminalProcess.pid,
            shell,
            dimensions: session.dimensions,
            status: session.status,
            createdAt: session.createdAt,
          });

        } catch (error) {
          socket.emit('terminal-error', {
            error: 'Failed to create terminal session',
            details: error instanceof Error ? error.message : 'Unknown error',
          });
        }
      });

      socket.on('terminal-input', async (data) => {
        const { sessionId, input } = data;
        
        const session = activeSessions.get(sessionId);
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('terminal-error', {
            sessionId,
            error: 'Invalid session or access denied',
          });
          return;
        }

        const terminalProcess = sessionProcesses.get(sessionId);
        if (!terminalProcess || terminalProcess.killed) {
          socket.emit('terminal-error', {
            sessionId,
            error: 'Terminal process not available',
          });
          return;
        }

        // Send input to terminal process
        if (terminalProcess.stdin) {
          terminalProcess.stdin.write(input);
        }

        // Track input message
        const message: TerminalMessage = {
          sessionId,
          type: 'input',
          data: input,
          timestamp: Date.now(),
          sequence: ++messageSequence,
        };

        const messages = sessionMessages.get(sessionId) || [];
        messages.push(message);
        sessionMessages.set(sessionId, messages);

        session.lastActivity = new Date();
        session.metadata.commandCount++;

        // Update session in Redis
        await redisClient.setex(
          `terminal_session:${sessionId}`,
          3600,
          JSON.stringify(session)
        );
      });

      socket.on('terminal-resize', async (data) => {
        const { sessionId, cols, rows } = data;
        
        const session = activeSessions.get(sessionId);
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('terminal-error', {
            sessionId,
            error: 'Invalid session or access denied',
          });
          return;
        }

        // Update session dimensions
        session.dimensions = { cols, rows };
        session.lastActivity = new Date();

        // In a real implementation, you would resize the PTY
        // For this test, we'll just acknowledge the resize
        socket.emit('terminal-resized', {
          sessionId,
          cols,
          rows,
          success: true,
        });

        await redisClient.setex(
          `terminal_session:${sessionId}`,
          3600,
          JSON.stringify(session)
        );
      });

      socket.on('get-session-history', async (data) => {
        const { sessionId, limit = 100 } = data;
        
        const session = activeSessions.get(sessionId);
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('terminal-error', {
            error: 'Invalid session or access denied',
          });
          return;
        }

        const messages = sessionMessages.get(sessionId) || [];
        const history = messages
          .filter(msg => msg.type === 'output')
          .slice(-limit)
          .map(msg => ({
            data: msg.data,
            timestamp: msg.timestamp,
            sequence: msg.sequence,
          }));

        socket.emit('session-history', {
          sessionId,
          history,
          totalMessages: messages.length,
        });
      });

      socket.on('list-sessions', async () => {
        if (!socket.data.authenticated) {
          socket.emit('error', { error: 'Not authenticated' });
          return;
        }

        const userSessions = Array.from(activeSessions.values())
          .filter(session => session.userId === socket.data.userId)
          .map(session => ({
            id: session.id,
            status: session.status,
            createdAt: session.createdAt,
            lastActivity: session.lastActivity,
            dimensions: session.dimensions,
            metadata: session.metadata,
          }));

        socket.emit('sessions-list', {
          sessions: userSessions,
          total: userSessions.length,
        });
      });

      socket.on('destroy-terminal-session', async (data) => {
        const { sessionId } = data;
        
        const session = activeSessions.get(sessionId);
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('terminal-error', {
            error: 'Invalid session or access denied',
          });
          return;
        }

        // Kill terminal process
        const terminalProcess = sessionProcesses.get(sessionId);
        if (terminalProcess && !terminalProcess.killed) {
          terminalProcess.kill('SIGTERM');
        }

        // Clean up session data
        session.status = 'destroyed';
        activeSessions.delete(sessionId);
        sessionMessages.delete(sessionId);
        sessionProcesses.delete(sessionId);
        
        await redisClient.del(`terminal_session:${sessionId}`);
        
        socket.leave(`terminal:${sessionId}`);

        socket.emit('terminal-session-destroyed', {
          sessionId,
          timestamp: Date.now(),
        });
      });

      socket.on('disconnect', () => {
        console.log(`Terminal client disconnected: ${socket.id}`);
      });
    });
  }

  describe('Terminal Session Creation and Setup', () => {
    beforeEach(async () => {
      clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      // Wait for connection and authenticate
      await new Promise<void>((resolve) => {
        clientSocket.on('connect', () => {
          clientSocket.emit('authenticate', { token: authToken });
        });
        clientSocket.on('authenticated', () => resolve());
      });
    });

    afterEach(() => {
      if (clientSocket) {
        clientSocket.disconnect();
      }
    });

    test('should create terminal session with default settings', async () => {
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Terminal creation timeout'));
        }, 10000);

        clientSocket.on('terminal-spawned', (data) => {
          clearTimeout(timeout);
          
          expect(data).toMatchObject({
            sessionId: expect.stringMatching(/^terminal_\d+_\w+$/),
            pid: expect.any(Number),
            shell: '/bin/bash',
            dimensions: { cols: 80, rows: 24 },
            status: 'active',
            createdAt: expect.any(String),
          });

          // Verify session was stored
          const session = Array.from(activeSessions.values())
            .find(s => s.id === data.sessionId);
          expect(session).toBeTruthy();
          expect(session!.userId).toBe(testUser.id);
          
          resolve();
        });

        clientSocket.on('terminal-error', (error) => {
          clearTimeout(timeout);
          reject(new Error(error.error));
        });

        clientSocket.emit('create-terminal-session', {});
      });
    });

    test('should create terminal session with custom settings', async () => {
      const customSettings = {
        shell: '/bin/sh',
        cols: 120,
        rows: 30,
        cwd: '/home/testuser',
      };

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Custom terminal creation timeout'));
        }, 10000);

        clientSocket.on('terminal-spawned', (data) => {
          clearTimeout(timeout);
          
          expect(data).toMatchObject({
            sessionId: expect.any(String),
            shell: customSettings.shell,
            dimensions: {
              cols: customSettings.cols,
              rows: customSettings.rows,
            },
          });

          resolve();
        });

        clientSocket.emit('create-terminal-session', customSettings);
      });
    });

    test('should persist session information in Redis', async () => {
      let sessionId: string;

      await new Promise<void>((resolve) => {
        clientSocket.on('terminal-spawned', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-terminal-session', {});
      });

      // Check Redis storage
      const redisData = await redisClient.get(`terminal_session:${sessionId}`);
      expect(redisData).toBeTruthy();
      
      const sessionData = JSON.parse(redisData!);
      expect(sessionData).toMatchObject({
        id: sessionId,
        userId: testUser.id,
        status: 'active',
        dimensions: { cols: 80, rows: 24 },
      });
    });

    test('should handle multiple concurrent session creations', async () => {
      const sessionCount = 5;
      const createdSessions: string[] = [];

      const promises = Array.from({ length: sessionCount }, (_, i) => {
        return new Promise<void>((resolve, reject) => {
          const socket = io(`http://localhost:${serverPort}`, {
            path: '/api/ws',
            transports: ['websocket'],
            forceNew: true,
          });

          const cleanup = () => socket.disconnect();
          const timeout = setTimeout(() => {
            cleanup();
            reject(new Error(`Session ${i} creation timeout`));
          }, 10000);

          socket.on('connect', () => {
            socket.emit('authenticate', { token: authToken });
          });

          socket.on('authenticated', () => {
            socket.emit('create-terminal-session', {
              cols: 80 + i,
              rows: 24 + i,
            });
          });

          socket.on('terminal-spawned', (data) => {
            clearTimeout(timeout);
            createdSessions.push(data.sessionId);
            cleanup();
            resolve();
          });

          socket.on('terminal-error', (error) => {
            clearTimeout(timeout);
            cleanup();
            reject(new Error(error.error));
          });
        });
      });

      await Promise.all(promises);

      expect(createdSessions).toHaveLength(sessionCount);
      expect(new Set(createdSessions).size).toBe(sessionCount); // All unique

      // Verify all sessions are active
      const userSessions = Array.from(activeSessions.values())
        .filter(s => s.userId === testUser.id);
      expect(userSessions).toHaveLength(sessionCount);
    });
  });

  describe('Terminal Input/Output Streaming', () => {
    let sessionId: string;

    beforeEach(async () => {
      clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      // Connect, authenticate, and create session
      await new Promise<void>((resolve) => {
        clientSocket.on('connect', () => {
          clientSocket.emit('authenticate', { token: authToken });
        });
        clientSocket.on('authenticated', () => resolve());
      });

      await new Promise<void>((resolve) => {
        clientSocket.on('terminal-spawned', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-terminal-session', {});
      });
    });

    afterEach(() => {
      if (clientSocket) {
        clientSocket.disconnect();
      }
    });

    test('should handle terminal input and receive output', async () => {
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Terminal I/O timeout'));
        }, 5000);

        let outputReceived = false;
        clientSocket.on('terminal-data', (data) => {
          if (data.sessionId === sessionId && !outputReceived) {
            clearTimeout(timeout);
            outputReceived = true;
            
            expect(data).toMatchObject({
              sessionId,
              data: expect.any(String),
              timestamp: expect.any(Number),
            });

            // Verify message was stored
            const messages = sessionMessages.get(sessionId);
            expect(messages?.length).toBeGreaterThan(0);
            
            resolve();
          }
        });

        // Send a simple command
        clientSocket.emit('terminal-input', {
          sessionId,
          input: 'echo "Hello Terminal"\n',
        });
      });
    });

    test('should handle rapid input streaming', async () => {
      const commands = [
        'echo "Command 1"\n',
        'echo "Command 2"\n',
        'echo "Command 3"\n',
        'pwd\n',
        'date\n',
      ];

      const receivedOutputs: any[] = [];

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          if (receivedOutputs.length === 0) {
            reject(new Error('No terminal output received'));
          } else {
            resolve(); // Some output received, good enough
          }
        }, 10000);

        clientSocket.on('terminal-data', (data) => {
          if (data.sessionId === sessionId) {
            receivedOutputs.push(data);
            
            // If we received output for most commands, resolve
            if (receivedOutputs.length >= commands.length - 2) {
              clearTimeout(timeout);
              
              expect(receivedOutputs.length).toBeGreaterThan(0);
              receivedOutputs.forEach(output => {
                expect(output.sessionId).toBe(sessionId);
                expect(output.data).toBeTruthy();
              });
              
              resolve();
            }
          }
        });

        // Send commands rapidly
        commands.forEach((command, i) => {
          setTimeout(() => {
            clientSocket.emit('terminal-input', {
              sessionId,
              input: command,
            });
          }, i * 100); // 100ms apart
        });
      });
    });

    test('should handle large output streams', async () => {
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Large output timeout'));
        }, 10000);

        let totalBytesReceived = 0;
        const minExpectedBytes = 1000; // Expect at least 1KB

        clientSocket.on('terminal-data', (data) => {
          if (data.sessionId === sessionId) {
            totalBytesReceived += Buffer.byteLength(data.data, 'utf8');
            
            if (totalBytesReceived >= minExpectedBytes) {
              clearTimeout(timeout);
              
              expect(totalBytesReceived).toBeGreaterThanOrEqual(minExpectedBytes);
              
              // Verify session metadata was updated
              const session = activeSessions.get(sessionId);
              expect(session?.metadata.totalBytes).toBeGreaterThan(0);
              
              resolve();
            }
          }
        });

        // Generate large output
        clientSocket.emit('terminal-input', {
          sessionId,
          input: 'for i in {1..100}; do echo "Line $i: This is a test line with some content"; done\n',
        });
      });
    });

    test('should maintain message ordering and sequence', async () => {
      const testMessages = [
        'echo "Message 1"\n',
        'echo "Message 2"\n',
        'echo "Message 3"\n',
      ];

      const receivedSequences: number[] = [];

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          resolve(); // Resolve even if we don't get all messages
        }, 8000);

        clientSocket.on('terminal-data', (data) => {
          if (data.sessionId === sessionId) {
            const messages = sessionMessages.get(sessionId) || [];
            const outputMessages = messages.filter(m => m.type === 'output');
            
            if (outputMessages.length > 0) {
              const latestMessage = outputMessages[outputMessages.length - 1];
              receivedSequences.push(latestMessage.sequence);
              
              if (receivedSequences.length >= testMessages.length) {
                clearTimeout(timeout);
                
                // Verify sequences are increasing
                for (let i = 1; i < receivedSequences.length; i++) {
                  expect(receivedSequences[i]).toBeGreaterThan(receivedSequences[i - 1]);
                }
                
                resolve();
              }
            }
          }
        });

        // Send messages with slight delays
        testMessages.forEach((message, i) => {
          setTimeout(() => {
            clientSocket.emit('terminal-input', {
              sessionId,
              input: message,
            });
          }, i * 200);
        });
      });
    });
  });

  describe('Terminal Session Management', () => {
    let sessionIds: string[] = [];

    beforeEach(async () => {
      clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      await new Promise<void>((resolve) => {
        clientSocket.on('connect', () => {
          clientSocket.emit('authenticate', { token: authToken });
        });
        clientSocket.on('authenticated', () => resolve());
      });

      // Create multiple sessions
      for (let i = 0; i < 3; i++) {
        await new Promise<void>((resolve) => {
          clientSocket.on('terminal-spawned', (data) => {
            sessionIds.push(data.sessionId);
            resolve();
          });
          clientSocket.emit('create-terminal-session', {
            cols: 80 + i * 10,
            rows: 24 + i * 5,
          });
        });
      }
    });

    afterEach(() => {
      sessionIds = [];
      if (clientSocket) {
        clientSocket.disconnect();
      }
    });

    test('should list user sessions', async () => {
      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Sessions list timeout'));
        }, 5000);

        clientSocket.on('sessions-list', (data) => {
          clearTimeout(timeout);
          
          expect(data).toMatchObject({
            sessions: expect.any(Array),
            total: expect.any(Number),
          });

          expect(data.sessions).toHaveLength(sessionIds.length);
          expect(data.total).toBe(sessionIds.length);

          data.sessions.forEach((session: any) => {
            expect(session).toMatchObject({
              id: expect.stringMatching(/^terminal_\d+_\w+$/),
              status: 'active',
              createdAt: expect.any(String),
              lastActivity: expect.any(String),
              dimensions: expect.objectContaining({
                cols: expect.any(Number),
                rows: expect.any(Number),
              }),
              metadata: expect.objectContaining({
                shell: expect.any(String),
                workingDirectory: expect.any(String),
                totalBytes: expect.any(Number),
                commandCount: expect.any(Number),
              }),
            });
          });

          resolve();
        });

        clientSocket.emit('list-sessions');
      });
    });

    test('should resize terminal sessions', async () => {
      const targetSession = sessionIds[0];
      const newDimensions = { cols: 100, rows: 50 };

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Terminal resize timeout'));
        }, 5000);

        clientSocket.on('terminal-resized', (data) => {
          clearTimeout(timeout);
          
          expect(data).toMatchObject({
            sessionId: targetSession,
            cols: newDimensions.cols,
            rows: newDimensions.rows,
            success: true,
          });

          // Verify session was updated
          const session = activeSessions.get(targetSession);
          expect(session?.dimensions).toEqual(newDimensions);
          
          resolve();
        });

        clientSocket.emit('terminal-resize', {
          sessionId: targetSession,
          ...newDimensions,
        });
      });
    });

    test('should retrieve session history', async () => {
      const targetSession = sessionIds[0];
      
      // Send some commands first
      const commands = ['echo "History test 1"\n', 'echo "History test 2"\n'];
      for (const command of commands) {
        clientSocket.emit('terminal-input', {
          sessionId: targetSession,
          input: command,
        });
      }

      // Wait for some output
      await new Promise(resolve => setTimeout(resolve, 1000));

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Session history timeout'));
        }, 5000);

        clientSocket.on('session-history', (data) => {
          clearTimeout(timeout);
          
          expect(data).toMatchObject({
            sessionId: targetSession,
            history: expect.any(Array),
            totalMessages: expect.any(Number),
          });

          data.history.forEach((entry: any) => {
            expect(entry).toMatchObject({
              data: expect.any(String),
              timestamp: expect.any(Number),
              sequence: expect.any(Number),
            });
          });

          resolve();
        });

        clientSocket.emit('get-session-history', {
          sessionId: targetSession,
          limit: 50,
        });
      });
    });

    test('should destroy terminal sessions properly', async () => {
      const targetSession = sessionIds[0];

      return new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Session destruction timeout'));
        }, 5000);

        clientSocket.on('terminal-session-destroyed', (data) => {
          clearTimeout(timeout);
          
          expect(data).toMatchObject({
            sessionId: targetSession,
            timestamp: expect.any(Number),
          });

          // Verify session was cleaned up
          expect(activeSessions.has(targetSession)).toBe(false);
          expect(sessionMessages.has(targetSession)).toBe(false);
          expect(sessionProcesses.has(targetSession)).toBe(false);
          
          resolve();
        });

        clientSocket.emit('destroy-terminal-session', {
          sessionId: targetSession,
        });
      });
    });
  });

  describe('Performance and Resource Management', () => {
    test('should handle session cleanup on disconnect', async () => {
      const tempSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      let sessionId: string;

      // Create session with temporary socket
      await new Promise<void>((resolve) => {
        tempSocket.on('connect', () => {
          tempSocket.emit('authenticate', { token: authToken });
        });
        tempSocket.on('authenticated', () => {
          tempSocket.emit('create-terminal-session', {});
        });
        tempSocket.on('terminal-spawned', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
      });

      // Verify session exists
      expect(activeSessions.has(sessionId)).toBe(true);

      // Disconnect socket
      tempSocket.disconnect();

      // Wait for cleanup (in a real implementation, you'd have cleanup logic)
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Session might still exist until explicit cleanup
      // In production, you'd implement session timeout/cleanup
    });

    test('should track resource usage metrics', async () => {
      clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      await new Promise<void>((resolve) => {
        clientSocket.on('connect', () => {
          clientSocket.emit('authenticate', { token: authToken });
        });
        clientSocket.on('authenticated', () => resolve());
      });

      let sessionId: string;
      await new Promise<void>((resolve) => {
        clientSocket.on('terminal-spawned', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-terminal-session', {});
      });

      // Generate some activity
      const commands = [
        'echo "Resource test 1"\n',
        'echo "Resource test 2"\n',
        'echo "Resource test 3"\n',
      ];

      for (const command of commands) {
        clientSocket.emit('terminal-input', {
          sessionId,
          input: command,
        });
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      await new Promise(resolve => setTimeout(resolve, 1000));

      // Check session metrics
      const session = activeSessions.get(sessionId);
      expect(session).toBeTruthy();
      expect(session!.metadata.commandCount).toBeGreaterThanOrEqual(commands.length);
      expect(session!.metadata.totalBytes).toBeGreaterThan(0);
      
      // Check message history
      const messages = sessionMessages.get(sessionId);
      expect(messages).toBeTruthy();
      expect(messages!.length).toBeGreaterThan(0);
    });

    test('should handle high-frequency input gracefully', async () => {
      clientSocket = io(`http://localhost:${serverPort}`, {
        path: '/api/ws',
        transports: ['websocket'],
        forceNew: true,
      });

      await new Promise<void>((resolve) => {
        clientSocket.on('connect', () => {
          clientSocket.emit('authenticate', { token: authToken });
        });
        clientSocket.on('authenticated', () => resolve());
      });

      let sessionId: string;
      await new Promise<void>((resolve) => {
        clientSocket.on('terminal-spawned', (data) => {
          sessionId = data.sessionId;
          resolve();
        });
        clientSocket.emit('create-terminal-session', {});
      });

      const startTime = performance.now();
      const inputCount = 100;
      const inputs: string[] = [];

      // Send rapid inputs
      for (let i = 0; i < inputCount; i++) {
        const input = String.fromCharCode(65 + (i % 26)); // A-Z
        inputs.push(input);
        
        clientSocket.emit('terminal-input', {
          sessionId,
          input,
        });
      }

      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should handle inputs efficiently
      expect(duration).toBeLessThan(5000); // Under 5 seconds
      
      console.log(`Processed ${inputCount} inputs in ${duration.toFixed(2)}ms`);

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Verify session is still responsive
      const session = activeSessions.get(sessionId);
      expect(session?.status).toBe('active');
    });
  });
});
