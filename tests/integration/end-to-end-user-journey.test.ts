/**
 * End-to-End User Journey Integration Tests
 *
 * These tests validate complete user workflows from start to finish,
 * simulating real user interactions across all application layers including
 * registration, authentication, terminal usage, session management, and cleanup.
 */

import request from 'supertest';
import { Application } from 'express';
import App from '../../rest-api/src/app';
import { database } from '../../rest-api/src/config/database';
import { redisClient } from '../../rest-api/src/config/redis';
import { User } from '../../rest-api/src/models/User';
import { ApiClient } from '../../src/lib/api/index';
import { WebSocketClient } from '../../src/lib/websocket/client';
import { io, Socket } from 'socket.io-client';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from '../../rest-api/src/config/environment';
import { performance } from 'perf_hooks';

// User journey tracking
interface UserJourney {
  userId: string;
  email: string;
  startTime: number;
  steps: JourneyStep[];
  completed: boolean;
  totalDuration?: number;
}

interface JourneyStep {
  name: string;
  timestamp: number;
  duration: number;
  success: boolean;
  data?: any;
  error?: string;
}

// Mock terminal session for E2E testing
interface E2ETerminalSession {
  id: string;
  userId: string;
  status: 'active' | 'inactive';
  createdAt: Date;
  commands: string[];
  outputs: string[];
}

describe('End-to-End User Journey Integration Tests', () => {
  let app: Application;
  let testApp: App;
  let httpServer: any;
  let socketServer: SocketIOServer;
  let serverPort: number;
  let apiClient: ApiClient;
  let wsClient: WebSocketClient;
  
  // Journey tracking
  const activeJourneys = new Map<string, UserJourney>();
  const completedJourneys: UserJourney[] = [];
  const terminalSessions = new Map<string, E2ETerminalSession>();

  // Test user templates
  const userTemplates = {
    newUser: {
      firstName: 'New',
      lastName: 'User',
      email: 'new.user@journey.test',
      password: 'NewUserPassword123!',
    },
    powerUser: {
      firstName: 'Power',
      lastName: 'User',
      email: 'power.user@journey.test',
      password: 'PowerUserPassword123!',
    },
    basicUser: {
      firstName: 'Basic',
      lastName: 'User',
      email: 'basic.user@journey.test',
      password: 'BasicUserPassword123!',
    },
  };

  beforeAll(async () => {
    // Initialize test environment
    process.env.NODE_ENV = 'test';
    process.env.DB_NAME = 'claude_flow_e2e_test';
    process.env.JWT_SECRET = 'test-e2e-jwt-secret';
    process.env.JWT_REFRESH_SECRET = 'test-e2e-refresh-secret';

    // Initialize app
    testApp = new App();
    app = testApp.app;

    await database.connect();
    await database.sync({ force: true });
    await redisClient.connect();

    // Set up WebSocket server for E2E testing
    httpServer = createServer(app);
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

    setupE2EWebSocketHandlers();
    
    // Initialize API client
    apiClient = new ApiClient(`http://localhost:${serverPort}/api/v1`);
  }, 30000);

  afterAll(async () => {
    // Cleanup all users and sessions
    await User.destroy({ where: {} });
    await database.disconnect();
    await redisClient.flushall();
    await redisClient.disconnect();
    await testApp.shutdown();
    
    if (wsClient) {
      wsClient.disconnect();
    }
    if (socketServer) {
      socketServer.close();
    }
    if (httpServer) {
      httpServer.close();
    }

    // Log journey analytics
    console.log(`\n📊 E2E Journey Analytics:`);
    console.log(`Total journeys completed: ${completedJourneys.length}`);
    if (completedJourneys.length > 0) {
      const avgDuration = completedJourneys.reduce((sum, j) => sum + (j.totalDuration || 0), 0) / completedJourneys.length;
      console.log(`Average journey duration: ${avgDuration.toFixed(2)}ms`);
    }
  }, 30000);

  beforeEach(async () => {
    // Clear session data but keep users for journey continuity
    terminalSessions.clear();
    await redisClient.flushall();
  });

  function setupE2EWebSocketHandlers() {
    socketServer.on('connection', (socket) => {
      socket.on('authenticate', async (data) => {
        try {
          const { token } = data;
          const decoded = jwt.verify(token, config.jwt.secret) as any;
          
          socket.data.userId = decoded.userId;
          socket.data.email = decoded.email;
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

      socket.on('create-terminal-session', (data) => {
        if (!socket.data.authenticated) {
          socket.emit('terminal-error', { error: 'Not authenticated' });
          return;
        }

        const sessionId = `e2e_terminal_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const session: E2ETerminalSession = {
          id: sessionId,
          userId: socket.data.userId,
          status: 'active',
          createdAt: new Date(),
          commands: [],
          outputs: [],
        };

        terminalSessions.set(sessionId, session);
        socket.join(`terminal:${sessionId}`);

        socket.emit('terminal-spawned', {
          sessionId,
          status: 'active',
          createdAt: session.createdAt,
        });
      });

      socket.on('terminal-input', (data) => {
        const { sessionId, input } = data;
        const session = terminalSessions.get(sessionId);
        
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('terminal-error', { error: 'Invalid session' });
          return;
        }

        session.commands.push(input.trim());
        
        // Simulate command processing
        let output = '';
        const command = input.trim();
        
        if (command === 'whoami') {
          output = 'testuser\n';
        } else if (command === 'pwd') {
          output = '/home/testuser\n';
        } else if (command === 'ls') {
          output = 'file1.txt  file2.txt  directory1/\n';
        } else if (command.startsWith('echo ')) {
          output = command.substring(5) + '\n';
        } else if (command === 'date') {
          output = new Date().toString() + '\n';
        } else if (command === 'clear') {
          output = '\x1b[2J\x1b[H';
        } else if (command === 'exit') {
          session.status = 'inactive';
          socket.emit('terminal-closed', {
            sessionId,
            code: 0,
            timestamp: Date.now(),
          });
          return;
        } else {
          output = `bash: ${command}: command not found\n`;
        }

        session.outputs.push(output);
        
        socket.emit('terminal-data', {
          sessionId,
          data: output,
          timestamp: Date.now(),
        });
      });

      socket.on('list-sessions', () => {
        if (!socket.data.authenticated) {
          socket.emit('error', { error: 'Not authenticated' });
          return;
        }

        const userSessions = Array.from(terminalSessions.values())
          .filter(session => session.userId === socket.data.userId)
          .map(session => ({
            id: session.id,
            status: session.status,
            createdAt: session.createdAt,
            commandCount: session.commands.length,
          }));

        socket.emit('sessions-list', {
          sessions: userSessions,
          total: userSessions.length,
        });
      });

      socket.on('destroy-terminal-session', (data) => {
        const { sessionId } = data;
        const session = terminalSessions.get(sessionId);
        
        if (!session || session.userId !== socket.data.userId) {
          socket.emit('error', { error: 'Invalid session' });
          return;
        }

        terminalSessions.delete(sessionId);
        socket.leave(`terminal:${sessionId}`);
        
        socket.emit('terminal-session-destroyed', {
          sessionId,
          timestamp: Date.now(),
        });
      });
    });
  }

  function startJourney(email: string): UserJourney {
    const journey: UserJourney = {
      userId: '',
      email,
      startTime: Date.now(),
      steps: [],
      completed: false,
    };
    
    activeJourneys.set(email, journey);
    return journey;
  }

  function addJourneyStep(email: string, name: string, success: boolean, data?: any, error?: string): JourneyStep {
    const journey = activeJourneys.get(email);
    if (!journey) {
      throw new Error(`No active journey for ${email}`);
    }

    const now = Date.now();
    const lastStep = journey.steps[journey.steps.length - 1];
    const duration = lastStep ? now - lastStep.timestamp : 0;

    const step: JourneyStep = {
      name,
      timestamp: now,
      duration,
      success,
      data,
      error,
    };

    journey.steps.push(step);
    return step;
  }

  function completeJourney(email: string): UserJourney {
    const journey = activeJourneys.get(email);
    if (!journey) {
      throw new Error(`No active journey for ${email}`);
    }

    journey.completed = true;
    journey.totalDuration = Date.now() - journey.startTime;
    
    activeJourneys.delete(email);
    completedJourneys.push(journey);
    
    return journey;
  }

  describe('New User Complete Journey', () => {
    test('should complete full new user workflow', async () => {
      const userData = userTemplates.newUser;
      const journey = startJourney(userData.email);
      
      try {
        // Step 1: User Registration
        console.log('🚀 Starting new user journey...');
        const registrationStart = performance.now();
        
        const registerResponse = await request(app)
          .post('/api/v1/auth/register')
          .send(userData)
          .expect(201);
        
        const registrationDuration = performance.now() - registrationStart;
        
        expect(registerResponse.body).toMatchObject({
          success: true,
          user: expect.objectContaining({
            email: userData.email.toLowerCase(),
            firstName: userData.firstName,
            lastName: userData.lastName,
          }),
          tokens: expect.objectContaining({
            accessToken: expect.any(String),
            refreshToken: expect.any(String),
          }),
        });

        journey.userId = registerResponse.body.user.id;
        const { accessToken, refreshToken } = registerResponse.body.tokens;
        
        addJourneyStep(userData.email, 'registration', true, {
          userId: journey.userId,
          duration: registrationDuration,
        });

        // Step 2: Profile Verification
        const profileResponse = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(200);

        expect(profileResponse.body.user).toMatchObject({
          id: journey.userId,
          email: userData.email.toLowerCase(),
          fullName: `${userData.firstName} ${userData.lastName}`,
        });

        addJourneyStep(userData.email, 'profile_verification', true);

        // Step 3: WebSocket Connection
        wsClient = new WebSocketClient(`http://localhost:${serverPort}`);
        await wsClient.connect();
        
        const authPromise = new Promise<void>((resolve, reject) => {
          wsClient.on('authenticated', () => resolve());
          wsClient.on('auth_error', (error) => reject(error));
        });
        
        wsClient.send('authenticate', { token: accessToken });
        await authPromise;

        addJourneyStep(userData.email, 'websocket_connection', true);

        // Step 4: Terminal Session Creation
        const terminalPromise = new Promise<string>((resolve, reject) => {
          wsClient.on('terminal-spawned', (data) => resolve(data.sessionId));
          wsClient.on('terminal-error', (error) => reject(error));
        });
        
        wsClient.send('create-terminal-session', { cols: 80, rows: 24 });
        const sessionId = await terminalPromise;

        expect(sessionId).toMatch(/^e2e_terminal_\d+_\w+$/);
        addJourneyStep(userData.email, 'terminal_creation', true, { sessionId });

        // Step 5: Terminal Interaction
        const commands = ['whoami', 'pwd', 'ls', 'echo "Hello World"'];
        const outputs: string[] = [];
        
        const outputPromise = new Promise<void>((resolve) => {
          let receivedOutputs = 0;
          wsClient.on('terminal-data', (data) => {
            if (data.sessionId === sessionId) {
              outputs.push(data.data);
              receivedOutputs++;
              
              if (receivedOutputs >= commands.length) {
                resolve();
              }
            }
          });
        });

        for (const command of commands) {
          wsClient.send('terminal-input', {
            sessionId,
            input: command + '\n',
          });
          await new Promise(resolve => setTimeout(resolve, 100));
        }

        await outputPromise;
        expect(outputs.length).toBeGreaterThanOrEqual(commands.length);
        addJourneyStep(userData.email, 'terminal_interaction', true, {
          commandsExecuted: commands.length,
          outputsReceived: outputs.length,
        });

        // Step 6: Session Management
        const sessionsPromise = new Promise<any>((resolve) => {
          wsClient.on('sessions-list', (data) => resolve(data));
        });
        
        wsClient.send('list-sessions');
        const sessionsList = await sessionsPromise;
        
        expect(sessionsList).toMatchObject({
          sessions: expect.arrayContaining([
            expect.objectContaining({ id: sessionId })
          ]),
          total: expect.any(Number),
        });

        addJourneyStep(userData.email, 'session_management', true, {
          totalSessions: sessionsList.total,
        });

        // Step 7: Token Refresh
        const refreshResponse = await request(app)
          .post('/api/v1/auth/refresh')
          .send({ refreshToken })
          .expect(200);

        expect(refreshResponse.body.tokens).toMatchObject({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
        });

        addJourneyStep(userData.email, 'token_refresh', true);

        // Step 8: Session Cleanup
        const destroyPromise = new Promise<void>((resolve) => {
          wsClient.on('terminal-session-destroyed', () => resolve());
        });
        
        wsClient.send('destroy-terminal-session', { sessionId });
        await destroyPromise;

        addJourneyStep(userData.email, 'session_cleanup', true);

        // Step 9: Logout
        const logoutResponse = await request(app)
          .post('/api/v1/auth/logout')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(200);

        expect(logoutResponse.body.success).toBe(true);
        addJourneyStep(userData.email, 'logout', true);

        // Complete journey
        const completedJourney = completeJourney(userData.email);
        
        console.log(`✅ New user journey completed in ${completedJourney.totalDuration}ms`);
        console.log(`📈 Journey steps: ${completedJourney.steps.map(s => s.name).join(' → ')}`);
        
        expect(completedJourney.steps).toHaveLength(9);
        expect(completedJourney.steps.every(step => step.success)).toBe(true);
        expect(completedJourney.totalDuration).toBeLessThan(30000); // Under 30 seconds

      } catch (error) {
        addJourneyStep(userData.email, 'error', false, undefined, error instanceof Error ? error.message : String(error));
        throw error;
      } finally {
        if (wsClient) {
          wsClient.disconnect();
        }
      }
    }, 60000);
  });

  describe('Power User Advanced Journey', () => {
    test('should handle power user multi-session workflow', async () => {
      const userData = userTemplates.powerUser;
      const journey = startJourney(userData.email);
      
      try {
        console.log('🔥 Starting power user journey...');
        
        // Step 1: Registration and Authentication
        const registerResponse = await request(app)
          .post('/api/v1/auth/register')
          .send(userData)
          .expect(201);

        journey.userId = registerResponse.body.user.id;
        const { accessToken } = registerResponse.body.tokens;
        addJourneyStep(userData.email, 'registration', true);

        // Step 2: Multiple WebSocket Connections (simulate multiple tabs)
        const connections: WebSocketClient[] = [];
        const connectionCount = 3;
        
        for (let i = 0; i < connectionCount; i++) {
          const client = new WebSocketClient(`http://localhost:${serverPort}`);
          await client.connect();
          
          await new Promise<void>((resolve, reject) => {
            client.on('authenticated', () => resolve());
            client.on('auth_error', (error) => reject(error));
            client.send('authenticate', { token: accessToken });
          });
          
          connections.push(client);
        }

        addJourneyStep(userData.email, 'multiple_connections', true, {
          connectionCount,
        });

        // Step 3: Create Multiple Terminal Sessions
        const sessionIds: string[] = [];
        
        for (let i = 0; i < connectionCount; i++) {
          const sessionId = await new Promise<string>((resolve, reject) => {
            connections[i].on('terminal-spawned', (data) => resolve(data.sessionId));
            connections[i].on('terminal-error', (error) => reject(error));
            connections[i].send('create-terminal-session', {
              cols: 100 + i * 10,
              rows: 30 + i * 5,
            });
          });
          
          sessionIds.push(sessionId);
        }

        expect(sessionIds).toHaveLength(connectionCount);
        addJourneyStep(userData.email, 'multiple_terminals', true, {
          sessionCount: sessionIds.length,
        });

        // Step 4: Concurrent Terminal Operations
        const concurrentCommands = [
          'echo "Terminal 1 active"',
          'echo "Terminal 2 active"',
          'echo "Terminal 3 active"',
        ];

        const outputPromises = sessionIds.map((sessionId, index) => {
          return new Promise<string>((resolve) => {
            connections[index].on('terminal-data', (data) => {
              if (data.sessionId === sessionId) {
                resolve(data.data);
              }
            });
            
            connections[index].send('terminal-input', {
              sessionId,
              input: concurrentCommands[index] + '\n',
            });
          });
        });

        const outputs = await Promise.all(outputPromises);
        expect(outputs).toHaveLength(connectionCount);
        addJourneyStep(userData.email, 'concurrent_operations', true, {
          outputsReceived: outputs.length,
        });

        // Step 5: Session List Verification
        const sessionsListPromise = new Promise<any>((resolve) => {
          connections[0].on('sessions-list', (data) => resolve(data));
        });
        
        connections[0].send('list-sessions');
        const sessionsList = await sessionsListPromise;
        
        expect(sessionsList.total).toBe(connectionCount);
        addJourneyStep(userData.email, 'session_verification', true, {
          expectedSessions: connectionCount,
          actualSessions: sessionsList.total,
        });

        // Step 6: Bulk Session Cleanup
        const cleanupPromises = sessionIds.map((sessionId, index) => {
          return new Promise<void>((resolve) => {
            connections[index].on('terminal-session-destroyed', () => resolve());
            connections[index].send('destroy-terminal-session', { sessionId });
          });
        });

        await Promise.all(cleanupPromises);
        addJourneyStep(userData.email, 'bulk_cleanup', true);

        // Cleanup connections
        connections.forEach(client => client.disconnect());

        const completedJourney = completeJourney(userData.email);
        console.log(`⚡ Power user journey completed in ${completedJourney.totalDuration}ms`);
        
        expect(completedJourney.steps.every(step => step.success)).toBe(true);
        expect(completedJourney.totalDuration).toBeLessThan(45000); // Under 45 seconds

      } catch (error) {
        addJourneyStep(userData.email, 'error', false, undefined, error instanceof Error ? error.message : String(error));
        throw error;
      }
    }, 90000);
  });

  describe('Error Recovery Journey', () => {
    test('should handle and recover from various error scenarios', async () => {
      const userData = userTemplates.basicUser;
      const journey = startJourney(userData.email);
      
      try {
        console.log('🛠️  Starting error recovery journey...');
        
        // Step 1: Successful Registration
        const registerResponse = await request(app)
          .post('/api/v1/auth/register')
          .send(userData)
          .expect(201);

        journey.userId = registerResponse.body.user.id;
        const { accessToken } = registerResponse.body.tokens;
        addJourneyStep(userData.email, 'registration', true);

        // Step 2: Test Invalid API Calls (should recover)
        try {
          await request(app)
            .get('/api/v1/nonexistent-endpoint')
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(404);
          
          addJourneyStep(userData.email, 'handled_404_error', true);
        } catch (error) {
          addJourneyStep(userData.email, 'handled_404_error', false, undefined, String(error));
        }

        // Step 3: Test WebSocket Connection with Invalid Token (should recover)
        wsClient = new WebSocketClient(`http://localhost:${serverPort}`);
        await wsClient.connect();
        
        // First, try with invalid token
        const authErrorPromise = new Promise<void>((resolve) => {
          wsClient.on('auth_error', () => {
            addJourneyStep(userData.email, 'handled_auth_error', true);
            resolve();
          });
        });
        
        wsClient.send('authenticate', { token: 'invalid-token' });
        await authErrorPromise;

        // Then authenticate properly
        const validAuthPromise = new Promise<void>((resolve, reject) => {
          wsClient.on('authenticated', () => resolve());
          wsClient.on('auth_error', (error) => reject(error));
        });
        
        wsClient.send('authenticate', { token: accessToken });
        await validAuthPromise;
        addJourneyStep(userData.email, 'recovered_auth', true);

        // Step 4: Test Terminal Operations with Invalid Session (should handle gracefully)
        wsClient.send('terminal-input', {
          sessionId: 'invalid-session-id',
          input: 'test command\n',
        });

        const errorPromise = new Promise<void>((resolve) => {
          wsClient.on('terminal-error', (error) => {
            expect(error.error).toContain('Invalid session');
            addJourneyStep(userData.email, 'handled_invalid_session', true);
            resolve();
          });
        });
        
        await errorPromise;

        // Step 5: Create Valid Terminal Session After Errors
        const terminalPromise = new Promise<string>((resolve) => {
          wsClient.on('terminal-spawned', (data) => resolve(data.sessionId));
        });
        
        wsClient.send('create-terminal-session', {});
        const sessionId = await terminalPromise;
        addJourneyStep(userData.email, 'terminal_recovery', true, { sessionId });

        // Step 6: Test Database Resilience (simulate temporary disconnection)
        await database.disconnect();
        
        // This should fail gracefully
        const dbErrorResponse = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(500);
        
        expect(dbErrorResponse.body.success).toBe(false);
        addJourneyStep(userData.email, 'handled_db_error', true);
        
        // Reconnect and verify recovery
        await database.connect();
        
        const recoveryResponse = await request(app)
          .get('/api/v1/auth/me')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(200);
        
        expect(recoveryResponse.body.user.id).toBe(journey.userId);
        addJourneyStep(userData.email, 'db_recovery', true);

        const completedJourney = completeJourney(userData.email);
        console.log(`🔧 Error recovery journey completed in ${completedJourney.totalDuration}ms`);
        
        // All error handling should have been successful
        expect(completedJourney.steps.every(step => step.success)).toBe(true);
        
      } catch (error) {
        addJourneyStep(userData.email, 'critical_error', false, undefined, error instanceof Error ? error.message : String(error));
        throw error;
      } finally {
        if (wsClient) {
          wsClient.disconnect();
        }
      }
    }, 60000);
  });

  describe('Performance and Stress Journey', () => {
    test('should handle high-load user journey efficiently', async () => {
      const userData = {
        firstName: 'Performance',
        lastName: 'Tester',
        email: 'performance.tester@journey.test',
        password: 'PerformanceTest123!',
      };
      
      const journey = startJourney(userData.email);
      
      try {
        console.log('⚡ Starting performance journey...');
        const journeyStart = performance.now();
        
        // Step 1: Rapid Registration (performance baseline)
        const regStart = performance.now();
        const registerResponse = await request(app)
          .post('/api/v1/auth/register')
          .send(userData)
          .expect(201);
        const regDuration = performance.now() - regStart;

        journey.userId = registerResponse.body.user.id;
        const { accessToken } = registerResponse.body.tokens;
        
        addJourneyStep(userData.email, 'fast_registration', true, {
          duration: regDuration,
        });

        // Step 2: Rapid API Calls
        const apiCallCount = 20;
        const apiStart = performance.now();
        
        const apiPromises = Array(apiCallCount).fill(null).map(() =>
          request(app)
            .get('/api/v1/auth/me')
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(200)
        );
        
        const apiResponses = await Promise.all(apiPromises);
        const apiDuration = performance.now() - apiStart;
        
        expect(apiResponses).toHaveLength(apiCallCount);
        addJourneyStep(userData.email, 'rapid_api_calls', true, {
          callCount: apiCallCount,
          totalDuration: apiDuration,
          avgDuration: apiDuration / apiCallCount,
        });

        // Step 3: High-Frequency WebSocket Operations
        wsClient = new WebSocketClient(`http://localhost:${serverPort}`);
        await wsClient.connect();
        
        await new Promise<void>((resolve, reject) => {
          wsClient.on('authenticated', () => resolve());
          wsClient.on('auth_error', (error) => reject(error));
          wsClient.send('authenticate', { token: accessToken });
        });

        const wsStart = performance.now();
        const messageCount = 100;
        let receivedCount = 0;
        
        const wsPromise = new Promise<void>((resolve) => {
          wsClient.on('terminal-data', () => {
            receivedCount++;
            if (receivedCount >= messageCount) {
              resolve();
            }
          });
        });
        
        // Create terminal session
        const sessionId = await new Promise<string>((resolve) => {
          wsClient.on('terminal-spawned', (data) => resolve(data.sessionId));
          wsClient.send('create-terminal-session', {});
        });

        // Send rapid messages
        for (let i = 0; i < messageCount; i++) {
          wsClient.send('terminal-input', {
            sessionId,
            input: `echo "Message ${i}"\n`,
          });
        }

        await wsPromise;
        const wsDuration = performance.now() - wsStart;
        
        addJourneyStep(userData.email, 'high_frequency_ws', true, {
          messageCount,
          receivedCount,
          duration: wsDuration,
          messagesPerSecond: messageCount / (wsDuration / 1000),
        });

        const totalJourneyTime = performance.now() - journeyStart;
        const completedJourney = completeJourney(userData.email);
        
        console.log(`🏁 Performance journey completed in ${totalJourneyTime.toFixed(2)}ms`);
        console.log(`📊 Performance metrics:`);
        console.log(`  Registration: ${regDuration.toFixed(2)}ms`);
        console.log(`  API calls (${apiCallCount}): ${apiDuration.toFixed(2)}ms avg: ${(apiDuration/apiCallCount).toFixed(2)}ms`);
        console.log(`  WebSocket (${messageCount} msgs): ${wsDuration.toFixed(2)}ms`);
        
        // Performance assertions
        expect(regDuration).toBeLessThan(2000); // Registration under 2s
        expect(apiDuration / apiCallCount).toBeLessThan(500); // API calls under 500ms each
        expect(wsDuration).toBeLessThan(10000); // WebSocket ops under 10s
        expect(completedJourney.totalDuration).toBeLessThan(20000); // Total under 20s
        
      } catch (error) {
        addJourneyStep(userData.email, 'performance_error', false, undefined, error instanceof Error ? error.message : String(error));
        throw error;
      } finally {
        if (wsClient) {
          wsClient.disconnect();
        }
      }
    }, 120000); // 2 minute timeout for performance test
  });

  describe('Journey Analytics and Reporting', () => {
    test('should provide comprehensive journey analytics', async () => {
      // This test runs after all other journeys to analyze the collected data
      
      expect(completedJourneys.length).toBeGreaterThan(0);
      
      console.log('\n📈 Journey Analytics Report:');
      console.log('================================');
      
      completedJourneys.forEach((journey, index) => {
        console.log(`\nJourney ${index + 1}: ${journey.email}`);
        console.log(`  Duration: ${journey.totalDuration}ms`);
        console.log(`  Steps: ${journey.steps.length}`);
        console.log(`  Success Rate: ${(journey.steps.filter(s => s.success).length / journey.steps.length * 100).toFixed(1)}%`);
        
        const stepSummary = journey.steps.map(step => 
          `${step.name}(${step.success ? '✓' : '✗'})`
        ).join(' → ');
        console.log(`  Flow: ${stepSummary}`);
      });
      
      // Calculate overall metrics
      const totalJourneys = completedJourneys.length;
      const avgDuration = completedJourneys.reduce((sum, j) => sum + (j.totalDuration || 0), 0) / totalJourneys;
      const totalSteps = completedJourneys.reduce((sum, j) => sum + j.steps.length, 0);
      const successfulSteps = completedJourneys.reduce((sum, j) => sum + j.steps.filter(s => s.success).length, 0);
      const overallSuccessRate = (successfulSteps / totalSteps) * 100;
      
      console.log('\n📊 Overall Metrics:');
      console.log(`  Total Journeys: ${totalJourneys}`);
      console.log(`  Average Duration: ${avgDuration.toFixed(2)}ms`);
      console.log(`  Total Steps: ${totalSteps}`);
      console.log(`  Overall Success Rate: ${overallSuccessRate.toFixed(1)}%`);
      
      // Assertions for journey quality
      expect(overallSuccessRate).toBeGreaterThan(95); // >95% success rate
      expect(avgDuration).toBeLessThan(60000); // <60s average
      expect(totalJourneys).toBeGreaterThanOrEqual(3); // At least 3 journeys completed
      
      // Step performance analysis
      const stepPerformance = new Map<string, { total: number; successful: number; avgDuration: number }>();
      
      completedJourneys.forEach(journey => {
        journey.steps.forEach(step => {
          const current = stepPerformance.get(step.name) || { total: 0, successful: 0, avgDuration: 0 };
          current.total++;
          if (step.success) current.successful++;
          current.avgDuration = (current.avgDuration * (current.total - 1) + step.duration) / current.total;
          stepPerformance.set(step.name, current);
        });
      });
      
      console.log('\n🎯 Step Performance:');
      stepPerformance.forEach((perf, stepName) => {
        const successRate = (perf.successful / perf.total) * 100;
        console.log(`  ${stepName}: ${successRate.toFixed(1)}% success, avg ${perf.avgDuration.toFixed(2)}ms`);
      });
      
      // Quality gates
      stepPerformance.forEach((perf, stepName) => {
        const successRate = (perf.successful / perf.total) * 100;
        expect(successRate).toBeGreaterThan(90); // Each step should have >90% success rate
      });
    });
  });
});
