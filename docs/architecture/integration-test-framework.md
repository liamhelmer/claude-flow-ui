# Integration Test Framework Design

## Framework Architecture Overview

The integration test framework validates cross-component interactions, API integrations, and real-time communication flows in the Claude Flow UI terminal application.

### Core Framework Principles

1. **Real Dependencies**: Use actual services where safe
2. **Data Flow Validation**: Test complete user journeys
3. **State Synchronization**: Verify cross-component consistency
4. **Performance Awareness**: Monitor integration performance
5. **Environment Isolation**: Predictable test environments

## Integration Test Categories

### 1. API Integration Tests

#### REST API Endpoint Testing

```typescript
// tests/integration/api-endpoints.integration.test.ts
import request from 'supertest';
import { app } from '@/server/app';
import { TestDatabase } from '@tests/helpers/test-database';
import { AuthHelper } from '@tests/helpers/auth-helper';

describe('API Endpoints Integration', () => {
  let testDb: TestDatabase;
  let authToken: string;

  beforeAll(async () => {
    testDb = new TestDatabase();
    await testDb.setup();
    authToken = await AuthHelper.getTestToken();
  });

  afterAll(async () => {
    await testDb.cleanup();
  });

  describe('Terminal Management API', () => {
    it('should create new terminal session', async () => {
      const response = await request(app)
        .post('/api/terminal/create')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          cols: 120,
          rows: 40,
          cwd: '/home/user'
        });

      expect(response.status).toBe(201);
      expect(response.body).toMatchObject({
        sessionId: expect.stringMatching(/^[a-f0-9-]{36}$/),
        status: 'active',
        config: {
          cols: 120,
          rows: 40,
          cwd: '/home/user'
        }
      });

      // Verify session was created in database
      const session = await testDb.findTerminalSession(response.body.sessionId);
      expect(session).toBeTruthy();
    });

    it('should list active terminal sessions', async () => {
      // Create test sessions
      await testDb.createTerminalSessions(3);

      const response = await request(app)
        .get('/api/terminal/list')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.sessions).toHaveLength(3);
      expect(response.body.sessions[0]).toMatchObject({
        sessionId: expect.any(String),
        status: 'active',
        createdAt: expect.any(String)
      });
    });

    it('should handle terminal session termination', async () => {
      const session = await testDb.createTerminalSession();

      const response = await request(app)
        .delete(`/api/terminal/${session.id}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Session terminated');

      // Verify session was marked as terminated
      const updatedSession = await testDb.findTerminalSession(session.id);
      expect(updatedSession.status).toBe('terminated');
    });
  });

  describe('Monitoring API', () => {
    it('should provide system metrics', async () => {
      const response = await request(app)
        .get('/api/monitoring/metrics')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        system: {
          cpu: expect.objectContaining({
            usage: expect.any(Number),
            cores: expect.any(Number)
          }),
          memory: expect.objectContaining({
            used: expect.any(Number),
            total: expect.any(Number),
            percentage: expect.any(Number)
          })
        },
        application: {
          activeSessions: expect.any(Number),
          uptime: expect.any(Number),
          version: expect.any(String)
        }
      });
    });
  });
});
```

### 2. WebSocket Integration Tests

#### Real-time Communication Flow

```typescript
// tests/integration/websocket-communication.integration.test.ts
import { io, Socket } from 'socket.io-client';
import { createTestServer } from '@tests/helpers/test-server';
import { WebSocketTestHelper } from '@tests/helpers/websocket-helper';

describe('WebSocket Communication Integration', () => {
  let server: any;
  let client: Socket;
  let wsHelper: WebSocketTestHelper;

  beforeAll(async () => {
    server = await createTestServer();
    wsHelper = new WebSocketTestHelper();
  });

  beforeEach(async () => {
    client = io('http://localhost:8080', {
      transports: ['websocket']
    });
    await wsHelper.waitForConnection(client);
  });

  afterEach(() => {
    client.disconnect();
  });

  afterAll(async () => {
    await server.close();
  });

  describe('Terminal Session Flow', () => {
    it('should establish terminal connection and exchange messages', async () => {
      // Join terminal session
      const sessionJoinPromise = wsHelper.waitForEvent(client, 'session:joined');
      client.emit('terminal:join', { sessionId: 'test-session-123' });
      const joinResponse = await sessionJoinPromise;

      expect(joinResponse).toMatchObject({
        sessionId: 'test-session-123',
        status: 'connected',
        config: expect.any(Object)
      });

      // Send terminal input
      const outputPromise = wsHelper.waitForEvent(client, 'terminal:output');
      client.emit('terminal:input', { data: 'echo "Hello World"\n' });
      const output = await outputPromise;

      expect(output.data).toContain('Hello World');
    });

    it('should handle multiple concurrent sessions', async () => {
      const clients = await Promise.all([
        wsHelper.createClient(),
        wsHelper.createClient(),
        wsHelper.createClient()
      ]);

      // Join different sessions
      const joinPromises = clients.map((client, index) => {
        const promise = wsHelper.waitForEvent(client, 'session:joined');
        client.emit('terminal:join', { sessionId: `session-${index}` });
        return promise;
      });

      const responses = await Promise.all(joinPromises);

      // Verify each client joined different sessions
      responses.forEach((response, index) => {
        expect(response.sessionId).toBe(`session-${index}`);
      });

      // Send input to one session, verify isolation
      const outputPromise = wsHelper.waitForEvent(clients[0], 'terminal:output');
      clients[0].emit('terminal:input', { data: 'unique-command\n' });
      const output = await outputPromise;

      // Verify other clients didn't receive this output
      const otherOutputs = await Promise.all([
        wsHelper.waitForEvent(clients[1], 'terminal:output', 100, false),
        wsHelper.waitForEvent(clients[2], 'terminal:output', 100, false)
      ]);

      expect(otherOutputs).toEqual([null, null]);

      // Cleanup
      clients.forEach(client => client.disconnect());
    });
  });

  describe('Connection Recovery', () => {
    it('should handle connection interruption and recovery', async () => {
      // Establish connection
      client.emit('terminal:join', { sessionId: 'recovery-test' });
      await wsHelper.waitForEvent(client, 'session:joined');

      // Simulate connection interruption
      client.disconnect();
      await wsHelper.wait(1000);

      // Reconnect
      client.connect();
      await wsHelper.waitForConnection(client);

      // Rejoin session
      const rejoinPromise = wsHelper.waitForEvent(client, 'session:rejoined');
      client.emit('terminal:rejoin', { sessionId: 'recovery-test' });
      const rejoinResponse = await rejoinPromise;

      expect(rejoinResponse).toMatchObject({
        sessionId: 'recovery-test',
        status: 'reconnected',
        missedMessages: expect.any(Array)
      });
    });
  });
});
```

### 3. Database Integration Tests

#### Transaction and State Management

```typescript
// tests/integration/database-transactions.integration.test.ts
import { DatabaseManager } from '@/lib/database/DatabaseManager';
import { TerminalService } from '@/services/TerminalService';
import { UserService } from '@/services/UserService';
import { TestDatabase } from '@tests/helpers/test-database';

describe('Database Transaction Integration', () => {
  let db: DatabaseManager;
  let testDb: TestDatabase;
  let terminalService: TerminalService;
  let userService: UserService;

  beforeAll(async () => {
    testDb = new TestDatabase();
    await testDb.setup();
    db = testDb.getManager();
    terminalService = new TerminalService(db);
    userService = new UserService(db);
  });

  afterAll(async () => {
    await testDb.cleanup();
  });

  beforeEach(async () => {
    await testDb.clearData();
  });

  describe('Terminal Session Lifecycle', () => {
    it('should create terminal session with user association', async () => {
      // Create user first
      const user = await userService.createUser({
        username: 'testuser',
        email: 'test@example.com'
      });

      // Create terminal session
      const session = await terminalService.createSession({
        userId: user.id,
        config: {
          cols: 120,
          rows: 40,
          cwd: '/home/testuser'
        }
      });

      // Verify database state
      expect(session).toMatchObject({
        id: expect.any(String),
        userId: user.id,
        status: 'active',
        config: expect.objectContaining({
          cols: 120,
          rows: 40
        })
      });

      // Verify relationships
      const userWithSessions = await userService.findWithSessions(user.id);
      expect(userWithSessions.sessions).toHaveLength(1);
      expect(userWithSessions.sessions[0].id).toBe(session.id);
    });

    it('should handle transaction rollback on failure', async () => {
      const user = await userService.createUser({
        username: 'testuser',
        email: 'test@example.com'
      });

      // Attempt to create session with invalid config (should fail)
      await expect(
        terminalService.createSession({
          userId: user.id,
          config: {
            cols: -1, // Invalid value
            rows: 40,
            cwd: '/invalid/path'
          }
        })
      ).rejects.toThrow();

      // Verify no session was created
      const userSessions = await terminalService.findByUser(user.id);
      expect(userSessions).toHaveLength(0);
    });
  });

  describe('Concurrent Access', () => {
    it('should handle concurrent session creation correctly', async () => {
      const user = await userService.createUser({
        username: 'testuser',
        email: 'test@example.com'
      });

      // Create multiple sessions concurrently
      const sessionPromises = Array.from({ length: 5 }, (_, index) =>
        terminalService.createSession({
          userId: user.id,
          config: {
            cols: 120,
            rows: 40,
            cwd: `/session-${index}`
          }
        })
      );

      const sessions = await Promise.all(sessionPromises);

      // Verify all sessions were created
      expect(sessions).toHaveLength(5);
      expect(new Set(sessions.map(s => s.id))).toHaveSize(5); // All unique

      // Verify user has all sessions
      const userWithSessions = await userService.findWithSessions(user.id);
      expect(userWithSessions.sessions).toHaveLength(5);
    });
  });
});
```

### 4. Cross-Component State Integration

#### React Component Data Flow

```typescript
// tests/integration/cross-component-data-flow.integration.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { AppLayout } from '@/components/AppLayout';
import { terminalReducer } from '@/store/terminalSlice';
import { monitoringReducer } from '@/store/monitoringSlice';
import { WebSocketTestProvider } from '@tests/helpers/websocket-test-provider';

describe('Cross-Component Data Flow Integration', () => {
  let store: any;

  beforeEach(() => {
    store = configureStore({
      reducer: {
        terminal: terminalReducer,
        monitoring: monitoringReducer
      }
    });
  });

  const renderApp = () => {
    return render(
      <Provider store={store}>
        <WebSocketTestProvider>
          <AppLayout />
        </WebSocketTestProvider>
      </Provider>
    );
  };

  describe('Terminal and Monitoring Integration', () => {
    it('should update monitoring data when terminal session starts', async () => {
      renderApp();

      // Start new terminal session
      const newTerminalButton = screen.getByRole('button', { name: /new terminal/i });
      fireEvent.click(newTerminalButton);

      // Wait for terminal to be created
      await waitFor(() => {
        expect(screen.getByRole('main', { name: /terminal/i })).toBeInTheDocument();
      });

      // Verify monitoring panel shows the new session
      await waitFor(() => {
        const monitoringPanel = screen.getByTestId('monitoring-panel');
        expect(monitoringPanel).toHaveTextContent('Active Sessions: 1');
      });
    });

    it('should synchronize terminal output with system metrics', async () => {
      renderApp();

      // Create terminal and run resource-intensive command
      const newTerminalButton = screen.getByRole('button', { name: /new terminal/i });
      fireEvent.click(newTerminalButton);

      const terminalInput = await screen.findByRole('textbox', { name: /terminal input/i });
      fireEvent.change(terminalInput, { target: { value: 'stress-test-command' } });
      fireEvent.keyDown(terminalInput, { key: 'Enter' });

      // Wait for command execution and metric updates
      await waitFor(() => {
        const cpuMetric = screen.getByTestId('cpu-usage');
        expect(parseFloat(cpuMetric.textContent!)).toBeGreaterThan(0);
      }, { timeout: 5000 });
    });
  });

  describe('Multi-Terminal Synchronization', () => {
    it('should maintain separate state for multiple terminals', async () => {
      renderApp();

      // Create two terminals
      const newTerminalButton = screen.getByRole('button', { name: /new terminal/i });
      fireEvent.click(newTerminalButton);
      fireEvent.click(newTerminalButton);

      // Wait for both terminals
      await waitFor(() => {
        const terminals = screen.getAllByRole('main', { name: /terminal/i });
        expect(terminals).toHaveLength(2);
      });

      // Send different commands to each terminal
      const terminals = screen.getAllByRole('main', { name: /terminal/i });
      const firstTerminalInput = terminals[0].querySelector('input');
      const secondTerminalInput = terminals[1].querySelector('input');

      fireEvent.change(firstTerminalInput!, { target: { value: 'pwd' } });
      fireEvent.keyDown(firstTerminalInput!, { key: 'Enter' });

      fireEvent.change(secondTerminalInput!, { target: { value: 'ls' } });
      fireEvent.keyDown(secondTerminalInput!, { key: 'Enter' });

      // Verify outputs are isolated
      await waitFor(() => {
        const firstOutput = terminals[0].querySelector('.terminal-output');
        const secondOutput = terminals[1].querySelector('.terminal-output');

        expect(firstOutput).toHaveTextContent('/home/user');
        expect(secondOutput).not.toHaveTextContent('/home/user');
        expect(secondOutput).toHaveTextContent('file1.txt');
      });
    });
  });
});
```

### 5. Authentication Flow Integration

#### End-to-End Auth Testing

```typescript
// tests/integration/auth-flow-integration.test.ts
import request from 'supertest';
import { app } from '@/server/app';
import { AuthService } from '@/services/AuthService';
import { TokenManager } from '@/lib/auth/TokenManager';
import { TestDatabase } from '@tests/helpers/test-database';

describe('Authentication Flow Integration', () => {
  let testDb: TestDatabase;
  let authService: AuthService;
  let tokenManager: TokenManager;

  beforeAll(async () => {
    testDb = new TestDatabase();
    await testDb.setup();
    authService = new AuthService(testDb.getManager());
    tokenManager = new TokenManager();
  });

  afterAll(async () => {
    await testDb.cleanup();
  });

  beforeEach(async () => {
    await testDb.clearUsers();
  });

  describe('Complete Authentication Flow', () => {
    it('should handle user registration, login, and authenticated requests', async () => {
      // 1. Register new user
      const registrationResponse = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'securepassword123'
        });

      expect(registrationResponse.status).toBe(201);
      expect(registrationResponse.body).toMatchObject({
        user: {
          id: expect.any(String),
          username: 'testuser',
          email: 'test@example.com'
        },
        message: 'User created successfully'
      });

      // 2. Login with credentials
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'securepassword123'
        });

      expect(loginResponse.status).toBe(200);
      expect(loginResponse.body).toMatchObject({
        token: expect.any(String),
        refreshToken: expect.any(String),
        user: {
          id: expect.any(String),
          username: 'testuser'
        }
      });

      const { token } = loginResponse.body;

      // 3. Use token for authenticated request
      const terminalResponse = await request(app)
        .post('/api/terminal/create')
        .set('Authorization', `Bearer ${token}`)
        .send({
          cols: 120,
          rows: 40,
          cwd: '/home/testuser'
        });

      expect(terminalResponse.status).toBe(201);
      expect(terminalResponse.body.sessionId).toBeTruthy();

      // 4. Verify token contains correct user info
      const decoded = tokenManager.verifyToken(token);
      expect(decoded).toMatchObject({
        userId: registrationResponse.body.user.id,
        username: 'testuser'
      });
    });

    it('should handle token refresh flow', async () => {
      // Create user and get tokens
      const user = await authService.createUser({
        username: 'refreshtest',
        email: 'refresh@example.com',
        password: 'password123'
      });

      const tokens = await authService.generateTokens(user.id);

      // Wait for access token to be near expiry (simulate)
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Use refresh token to get new access token
      const refreshResponse = await request(app)
        .post('/api/auth/refresh')
        .send({
          refreshToken: tokens.refreshToken
        });

      expect(refreshResponse.status).toBe(200);
      expect(refreshResponse.body).toMatchObject({
        token: expect.any(String),
        refreshToken: expect.any(String)
      });

      // Verify new token works
      const testResponse = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${refreshResponse.body.token}`);

      expect(testResponse.status).toBe(200);
      expect(testResponse.body.user.id).toBe(user.id);
    });
  });

  describe('Security Integration', () => {
    it('should reject requests with invalid tokens', async () => {
      const invalidToken = 'invalid.jwt.token';

      const response = await request(app)
        .get('/api/terminal/list')
        .set('Authorization', `Bearer ${invalidToken}`);

      expect(response.status).toBe(401);
      expect(response.body).toMatchObject({
        error: 'Invalid token'
      });
    });

    it('should handle concurrent login attempts', async () => {
      const user = await authService.createUser({
        username: 'concurrenttest',
        email: 'concurrent@example.com',
        password: 'password123'
      });

      // Simulate multiple concurrent login attempts
      const loginPromises = Array.from({ length: 10 }, () =>
        request(app)
          .post('/api/auth/login')
          .send({
            email: 'concurrent@example.com',
            password: 'password123'
          })
      );

      const responses = await Promise.all(loginPromises);

      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.token).toBeTruthy();
      });

      // Verify all tokens are valid and different
      const tokens = responses.map(r => r.body.token);
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(10); // All tokens should be unique
    });
  });
});
```

## Integration Test Helpers

### Database Test Helper

```typescript
// tests/helpers/test-database.ts
import { DatabaseManager } from '@/lib/database/DatabaseManager';
import { migrations } from '@/database/migrations';

export class TestDatabase {
  private manager: DatabaseManager;
  private dbName: string;

  constructor() {
    this.dbName = `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.manager = new DatabaseManager({
      database: `:memory:`, // SQLite in-memory for testing
      logging: false
    });
  }

  async setup(): Promise<void> {
    await this.manager.initialize();
    await this.runMigrations();
    await this.seedTestData();
  }

  async cleanup(): Promise<void> {
    await this.manager.close();
  }

  async clearData(): Promise<void> {
    const tables = ['terminal_sessions', 'users', 'session_logs'];
    for (const table of tables) {
      await this.manager.query(`DELETE FROM ${table}`);
    }
  }

  getManager(): DatabaseManager {
    return this.manager;
  }

  // Helper methods for test data creation
  async createUser(userData: any) {
    return this.manager.getRepository('User').create(userData);
  }

  async createTerminalSession(sessionData: any) {
    return this.manager.getRepository('TerminalSession').create(sessionData);
  }

  async findTerminalSession(id: string) {
    return this.manager.getRepository('TerminalSession').findById(id);
  }

  private async runMigrations(): Promise<void> {
    for (const migration of migrations) {
      await migration.up(this.manager.queryRunner);
    }
  }

  private async seedTestData(): Promise<void> {
    // Seed common test data
    await this.createUser({
      username: 'testuser',
      email: 'test@example.com',
      password: 'hashedpassword'
    });
  }
}
```

### WebSocket Test Helper

```typescript
// tests/helpers/websocket-helper.ts
import { io, Socket } from 'socket.io-client';

export class WebSocketTestHelper {
  private clients: Socket[] = [];

  async createClient(options = {}): Promise<Socket> {
    const client = io('http://localhost:8080', {
      transports: ['websocket'],
      forceNew: true,
      ...options
    });

    this.clients.push(client);
    await this.waitForConnection(client);
    return client;
  }

  async waitForConnection(client: Socket): Promise<void> {
    return new Promise((resolve, reject) => {
      if (client.connected) {
        resolve();
        return;
      }

      const timeout = setTimeout(() => {
        reject(new Error('Connection timeout'));
      }, 5000);

      client.on('connect', () => {
        clearTimeout(timeout);
        resolve();
      });
    });
  }

  async waitForEvent(
    client: Socket,
    event: string,
    timeout = 5000,
    shouldTimeout = true
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (shouldTimeout) {
          reject(new Error(`Timeout waiting for event: ${event}`));
        } else {
          resolve(null);
        }
      }, timeout);

      client.once(event, (data) => {
        clearTimeout(timer);
        resolve(data);
      });
    });
  }

  async wait(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  cleanup(): void {
    this.clients.forEach(client => {
      if (client.connected) {
        client.disconnect();
      }
    });
    this.clients = [];
  }
}
```

This integration test framework provides comprehensive coverage of cross-component interactions while maintaining clear separation between unit tests and integration tests. The framework focuses on real-world scenarios and ensures data consistency across the entire application stack.