# Test Architecture Design Document
**Claude Flow UI Test Architecture & Strategy**

## Overview

This document defines a comprehensive test architecture for the claude-flow-ui project, establishing a multi-layered testing strategy that ensures reliability, performance, and security of the terminal interface, REST API, and WebSocket communication systems.

## Architecture Decision Records (ADRs)

### ADR-TEST-001: Multi-Layer Testing Strategy
**Status:** Approved
**Context:** Need systematic testing approach for complex WebSocket/terminal application
**Decision:** Implement 5-layer testing pyramid with emphasis on integration and E2E testing
**Rationale:**
- Complex real-time WebSocket communication requires extensive integration testing
- Terminal emulation needs thorough E2E validation
- Security is critical for terminal access
- Performance testing essential for real-time applications

### ADR-TEST-002: Testing Framework Selection
**Status:** Approved
**Context:** Choose optimal testing tools for JavaScript/Node.js application
**Decision:** Jest + Playwright + k6 + OWASP ZAP stack
**Rationale:**
- Jest: Excellent Node.js support, built-in mocking, good performance
- Playwright: Superior WebSocket testing, cross-browser support
- k6: Load testing with WebSocket support
- OWASP ZAP: Industry-standard security scanning

### ADR-TEST-003: Test Environment Strategy
**Status:** Approved
**Context:** Ensure consistent testing across environments
**Decision:** Containerized test environments with Docker Compose
**Rationale:**
- Consistent environment across dev/CI/CD
- Easy tmux/terminal dependency management
- Isolated test execution
- Parallel test execution capability

## Test Architecture Layers

### Layer 1: Unit Tests (40% Coverage Target)
**Purpose:** Test individual components and utilities in isolation
**Framework:** Jest with jsdom
**Target Coverage:** >85% line coverage for utilities, >80% for components

#### Scope:
- **Utility Functions** (`src/lib/`, `src/utils/`)
  - Terminal configuration parsing
  - ANSI escape sequence handling
  - Session management utilities
  - WebSocket connection helpers

- **React Components** (`src/components/`)
  - Terminal component rendering
  - Sidebar navigation
  - Configuration panels
  - Error boundaries

- **Hooks** (`src/hooks/`)
  - WebSocket connection hooks
  - Terminal state management
  - Configuration management

#### Key Patterns:
```javascript
// Example unit test structure
describe('TerminalConfig', () => {
  describe('parseTerminalSize', () => {
    it('should parse valid terminal size string', () => {
      expect(parseTerminalSize('120x40')).toEqual({ cols: 120, rows: 40 });
    });

    it('should handle invalid size gracefully', () => {
      expect(parseTerminalSize('invalid')).toEqual({ cols: 80, rows: 24 });
    });
  });
});
```

### Layer 2: Integration Tests (30% Coverage Target)
**Purpose:** Test component interactions, API endpoints, and WebSocket connections
**Framework:** Jest + Supertest + Socket.IO Client

#### Scope:
- **API Endpoint Integration**
  - `/api/health` - Health check functionality
  - `/api/terminal-config` - Configuration management
  - `/api/terminals` - Terminal lifecycle management
  - REST API error handling and validation

- **WebSocket Integration**
  - Connection establishment and handshake
  - Message routing and broadcasting
  - Session switching and multiplexing
  - Error propagation and recovery

- **Terminal Backend Integration**
  - Tmux session management
  - PTY fallback mechanisms
  - Process lifecycle management
  - Data streaming and buffering

#### Example Test Structure:
```javascript
describe('WebSocket Terminal Integration', () => {
  let server, client;

  beforeEach(async () => {
    server = await startTestServer();
    client = await connectWebSocketClient();
  });

  it('should establish terminal session and stream data', async () => {
    // Test terminal creation, data flow, and cleanup
  });
});
```

### Layer 3: End-to-End Tests (20% Coverage Target)
**Purpose:** Test complete user workflows and system behavior
**Framework:** Playwright with WebSocket support

#### Scope:
- **User Journey Testing**
  - Terminal interface loading and initialization
  - Multi-terminal creation and switching
  - Command execution and output validation
  - Real-time terminal interaction

- **Cross-Browser Compatibility**
  - Chrome, Firefox, Safari support
  - WebSocket transport fallbacks
  - Terminal rendering consistency

- **Error Scenario Testing**
  - Network disconnection handling
  - Server restart recovery
  - Terminal crash recovery

#### Example Test Structure:
```javascript
// tests/e2e/terminal-workflow.spec.ts
test('complete terminal workflow', async ({ page }) => {
  await page.goto('/');

  // Test terminal loading
  await expect(page.locator('[data-testid="terminal"]')).toBeVisible();

  // Test command execution
  await page.locator('[data-testid="terminal"]').click();
  await page.keyboard.type('echo "Hello World"');
  await page.keyboard.press('Enter');

  // Validate output
  await expect(page.locator('[data-testid="terminal"]')).toContainText('Hello World');
});
```

### Layer 4: Performance Tests (5% Coverage Target)
**Purpose:** Validate system performance under load and stress conditions
**Framework:** k6 with WebSocket support

#### Scope:
- **Load Testing**
  - Concurrent WebSocket connections (target: 100+ clients)
  - Terminal data throughput testing
  - Memory usage under sustained load
  - API endpoint response times

- **Stress Testing**
  - Maximum concurrent sessions
  - Large data payload handling
  - Resource exhaustion scenarios
  - Recovery from overload conditions

#### Example Performance Test:
```javascript
// tests/performance/websocket-load.js
import ws from 'k6/ws';

export let options = {
  stages: [
    { duration: '2m', target: 50 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 0 },
  ],
};

export default function() {
  const url = 'ws://localhost:8080/api/ws';
  const res = ws.connect(url, function(socket) {
    socket.on('open', () => {
      // Simulate terminal interaction
      socket.send(JSON.stringify({
        sessionId: 'perf-test',
        data: 'echo "Performance test"'
      }));
    });
  });
}
```

### Layer 5: Security Tests (5% Coverage Target)
**Purpose:** Identify vulnerabilities and ensure secure operation
**Framework:** OWASP ZAP + Custom security tests

#### Scope:
- **WebSocket Security**
  - Input validation and sanitization
  - Command injection prevention
  - Session hijacking protection
  - Authentication bypass testing

- **API Security**
  - Input validation on all endpoints
  - Rate limiting effectiveness
  - CORS policy validation
  - Error information disclosure

- **Terminal Security**
  - Escape sequence injection
  - Path traversal prevention
  - Privilege escalation testing
  - Process isolation validation

#### Example Security Test:
```javascript
// tests/security/input-validation.test.js
describe('Input Validation Security', () => {
  it('should prevent command injection via WebSocket', async () => {
    const maliciousInput = '; rm -rf /; echo "hacked"';

    const response = await sendWebSocketMessage({
      sessionId: 'test',
      data: maliciousInput
    });

    // Should be sanitized or rejected
    expect(response.error).toBeDefined();
  });
});
```

## Testing Frameworks and Tools

### Core Testing Stack

#### Jest (Unit & Integration Testing)
**Version:** ^30.0.5
**Configuration:**
- Environment: jsdom for React components, node for backend
- Coverage threshold: 80% lines, 70% branches
- Parallel execution with 50% CPU utilization
- Mock and spy capabilities for external dependencies

#### Playwright (E2E Testing)
**Version:** ^1.55.0
**Configuration:**
- Multi-browser testing (Chromium, Firefox, WebKit)
- WebSocket testing capabilities
- Visual regression testing
- Mobile viewport testing

#### k6 (Performance Testing)
**Version:** Latest
**Capabilities:**
- WebSocket load testing
- HTTP API performance testing
- Custom metrics collection
- CI/CD integration

#### OWASP ZAP (Security Testing)
**Configuration:**
- Automated security scans
- WebSocket security testing
- API endpoint security validation
- Vulnerability reporting

### Supporting Tools

#### Supertest (API Testing)
```javascript
const request = require('supertest');
const app = require('../unified-server');

test('health endpoint', async () => {
  const response = await request(app)
    .get('/api/health')
    .expect(200);

  expect(response.body.status).toBe('ok');
});
```

#### Socket.IO Test Utils (WebSocket Testing)
```javascript
const { io: Client } = require('socket.io-client');

const client = Client('http://localhost:8080/api/ws', {
  transports: ['websocket']
});
```

## Test Data Management Strategy

### Mock Data Patterns

#### Terminal Session Mocks
```javascript
// tests/mocks/terminalSessions.js
export const mockTerminalSessions = {
  basic: {
    id: 'term-123',
    name: 'Terminal 1',
    command: '/bin/bash',
    createdAt: new Date('2025-01-15'),
    isClaudeFlow: false
  },
  claudeFlow: {
    id: 'cf-456',
    name: 'Claude Flow',
    command: 'npx claude-flow',
    createdAt: new Date('2025-01-15'),
    isClaudeFlow: true
  }
};
```

#### WebSocket Message Mocks
```javascript
// tests/mocks/websocketMessages.js
export const mockWebSocketMessages = {
  terminalData: (sessionId, data) => ({
    sessionId,
    data,
    timestamp: Date.now()
  }),
  systemMetrics: {
    memoryUsage: 70,
    cpuLoad: 1.5,
    activeConnections: 5
  }
};
```

### Test Database Strategy
- **In-Memory Database:** SQLite for integration tests
- **Test Data Seeding:** Automated seed scripts for consistent test data
- **Cleanup Strategy:** Automatic database reset between test suites

### Fixture Management
```javascript
// tests/fixtures/terminalOutput.js
export const terminalOutputFixtures = {
  bashPrompt: '$ ',
  longOutput: 'x'.repeat(10000),
  ansiColors: '\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m',
  multiline: 'Line 1\nLine 2\nLine 3'
};
```

## Test Environment Configuration

### Docker Test Environment
```yaml
# docker-compose.test.yml
version: '3.8'
services:
  test-app:
    build: .
    environment:
      - NODE_ENV=test
      - PORT=8080
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
      - postgres
    ports:
      - "8080:8080"

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: claude_flow_test
      POSTGRES_USER: test
      POSTGRES_PASSWORD: test
    ports:
      - "5432:5432"
```

### Environment Variables for Testing
```bash
# .env.test
NODE_ENV=test
PORT=8080
WS_PORT=8081
DB_URL=postgresql://test:test@localhost:5432/claude_flow_test
REDIS_URL=redis://localhost:6379
LOG_LEVEL=error
DISABLE_TMUX=false
TEST_TIMEOUT=30000
```

### CI/CD Integration Points

#### GitHub Actions Configuration
```yaml
# .github/workflows/test.yml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      redis:
        image: redis
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    strategy:
      matrix:
        node-version: [18, 20]
        test-suite: [unit, integration, e2e]

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - run: npm ci
      - run: npm run test:${{ matrix.test-suite }}
      - run: npm run test:coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

#### Test Stages Pipeline
1. **Static Analysis:** ESLint, TypeScript checking
2. **Unit Tests:** Fast feedback loop (< 2 minutes)
3. **Integration Tests:** API and WebSocket validation (< 5 minutes)
4. **E2E Tests:** Critical user journeys (< 10 minutes)
5. **Performance Tests:** Load testing (< 15 minutes)
6. **Security Tests:** Vulnerability scanning (< 5 minutes)

## Test Organization and Naming Conventions

### Directory Structure
```
tests/
├── unit/                     # Unit tests
│   ├── components/           # React component tests
│   ├── lib/                  # Utility function tests
│   └── hooks/                # React hooks tests
├── integration/              # Integration tests
│   ├── api/                  # REST API tests
│   ├── websocket/            # WebSocket tests
│   └── backend/              # Backend integration tests
├── e2e/                      # End-to-end tests
│   ├── workflows/            # User journey tests
│   ├── cross-browser/        # Browser compatibility
│   └── regression/           # Regression test suites
├── performance/              # Performance tests
│   ├── load/                 # Load testing
│   ├── stress/               # Stress testing
│   └── benchmarks/           # Performance benchmarks
├── security/                 # Security tests
│   ├── input-validation/     # Input validation tests
│   ├── authentication/       # Auth security tests
│   └── vulnerabilities/      # Vulnerability tests
├── mocks/                    # Mock data and utilities
│   ├── websocket/            # WebSocket mocks
│   ├── terminal/             # Terminal mocks
│   └── api/                  # API mocks
├── fixtures/                 # Test data fixtures
├── utils/                    # Test utilities
└── setup/                    # Test setup and configuration
```

### Naming Conventions

#### Test File Naming
- **Unit Tests:** `component-name.test.js`
- **Integration Tests:** `feature-integration.test.js`
- **E2E Tests:** `workflow-name.spec.js`
- **Performance Tests:** `load-scenario.perf.js`
- **Security Tests:** `security-feature.security.test.js`

#### Test Description Patterns
```javascript
describe('ComponentName', () => {
  describe('when condition', () => {
    it('should perform expected behavior', () => {
      // Test implementation
    });
  });
});
```

#### Test Data Naming
```javascript
const mockTerminalSession = {
  id: 'test-session-123',
  name: 'Test Terminal',
  // ...
};

const expectedWebSocketResponse = {
  sessionId: 'expected-session',
  data: 'expected output',
  // ...
};
```

## Shared Test Utilities and Helpers

### WebSocket Test Helper
```javascript
// tests/utils/websocketHelper.js
export class WebSocketTestHelper {
  constructor(port = 8080) {
    this.port = port;
    this.clients = new Map();
  }

  async createClient(clientId) {
    const client = Client(`http://localhost:${this.port}/api/ws`);

    await new Promise((resolve) => {
      client.on('connect', resolve);
    });

    this.clients.set(clientId, client);
    return client;
  }

  async cleanupClients() {
    for (const client of this.clients.values()) {
      client.disconnect();
    }
    this.clients.clear();
  }
}
```

### Terminal Test Helper
```javascript
// tests/utils/terminalHelper.js
export class TerminalTestHelper {
  static createMockSession(overrides = {}) {
    return {
      id: `test-${Date.now()}`,
      name: 'Test Terminal',
      command: '/bin/bash',
      createdAt: new Date(),
      isClaudeFlow: false,
      ...overrides
    };
  }

  static simulateTerminalOutput(data, delay = 100) {
    return new Promise((resolve) => {
      setTimeout(() => resolve(data), delay);
    });
  }
}
```

### API Test Helper
```javascript
// tests/utils/apiHelper.js
export class APITestHelper {
  constructor(app) {
    this.request = request(app);
  }

  async createTerminal(config = {}) {
    const response = await this.request
      .post('/api/terminals/spawn')
      .send({
        name: 'Test Terminal',
        command: '/bin/bash',
        ...config
      });

    return response.body;
  }

  async getTerminals() {
    const response = await this.request.get('/api/terminals');
    return response.body;
  }
}
```

## Test Database and Fixture Management

### Test Database Setup
```javascript
// tests/setup/database.js
export class TestDatabase {
  static async setup() {
    // Create test database
    await createTestDatabase();

    // Run migrations
    await runMigrations();

    // Seed test data
    await seedTestData();
  }

  static async teardown() {
    await dropTestDatabase();
  }

  static async reset() {
    await clearTestData();
    await seedTestData();
  }
}
```

### Fixture Management
```javascript
// tests/fixtures/index.js
export const fixtures = {
  terminals: {
    basic: () => ({
      id: uuid(),
      name: 'Test Terminal',
      command: '/bin/bash',
      createdAt: new Date()
    }),
    claudeFlow: () => ({
      id: uuid(),
      name: 'Claude Flow',
      command: 'npx claude-flow',
      isClaudeFlow: true,
      createdAt: new Date()
    })
  },

  websocketMessages: {
    terminalData: (sessionId, data) => ({
      sessionId,
      data,
      timestamp: Date.now()
    })
  }
};
```

## Parallel Test Execution Strategy

### Jest Parallel Configuration
```javascript
// jest.config.js
module.exports = {
  // Use 50% of available cores
  maxWorkers: "50%",

  // Enable parallel execution
  runInBand: false,

  // Test timeout optimization
  testTimeout: 30000,

  // Cache optimization
  cacheDirectory: "node_modules/.cache/jest",

  // Projects for parallel execution
  projects: [
    {
      displayName: "unit",
      testMatch: ["<rootDir>/tests/unit/**/*.test.js"]
    },
    {
      displayName: "integration",
      testMatch: ["<rootDir>/tests/integration/**/*.test.js"]
    }
  ]
};
```

### Test Execution Optimization
```javascript
// tests/utils/testOptimization.js
export class TestOptimizer {
  static async beforeAll() {
    // Pre-warm connections
    await this.prewarmConnections();

    // Setup shared resources
    await this.setupSharedResources();
  }

  static async afterAll() {
    // Cleanup shared resources
    await this.cleanupSharedResources();
  }

  static async prewarmConnections() {
    // Pre-establish database connections
    // Pre-warm HTTP server
    // Initialize WebSocket connections
  }
}
```

## Test Reporting and Monitoring

### Coverage Reporting
```javascript
// jest.config.js
module.exports = {
  collectCoverageFrom: [
    "src/**/*.{js,jsx,ts,tsx}",
    "!src/**/*.d.ts",
    "!src/**/*.stories.{js,jsx,ts,tsx}",
  ],

  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80
    },
    "src/lib/": {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90
    }
  },

  coverageReporters: [
    "text",
    "lcov",
    "html",
    "json-summary"
  ]
};
```

### Test Result Dashboard
```yaml
# .github/workflows/test-reporting.yml
- name: Generate Test Report
  uses: dorny/test-reporter@v1
  if: success() || failure()
  with:
    name: Jest Tests
    path: 'test-results/*.xml'
    reporter: jest-junit

- name: Coverage Report
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage/lcov.info
    flags: unittests
    name: codecov-umbrella
```

### Performance Monitoring
```javascript
// tests/utils/performanceMonitor.js
export class PerformanceMonitor {
  static async measureWebSocketLatency() {
    const start = performance.now();
    // Perform WebSocket operation
    const end = performance.now();
    return end - start;
  }

  static async measureAPIResponseTime(endpoint) {
    const start = performance.now();
    await fetch(endpoint);
    const end = performance.now();
    return end - start;
  }
}
```

## REST API Testing Strategy

### Comprehensive API Test Coverage

#### Health Check Endpoint
```javascript
// tests/integration/api/health.test.js
describe('GET /api/health', () => {
  it('should return system health status', async () => {
    const response = await request(app)
      .get('/api/health')
      .expect(200);

    expect(response.body).toEqual({
      status: 'ok',
      timestamp: expect.any(String),
      services: {
        api: 'running',
        websocket: 'running',
        terminal: 'running'
      }
    });
  });

  it('should handle service failures gracefully', async () => {
    // Mock service failure
    const response = await request(app)
      .get('/api/health')
      .expect(503);

    expect(response.body.status).toBe('degraded');
  });
});
```

#### Terminal Management API
```javascript
// tests/integration/api/terminals.test.js
describe('Terminal API Endpoints', () => {
  describe('GET /api/terminals', () => {
    it('should list all active terminals', async () => {
      const response = await request(app)
        .get('/api/terminals')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('POST /api/terminals/spawn', () => {
    it('should create new terminal session', async () => {
      const terminalConfig = {
        name: 'Test Terminal',
        command: '/bin/bash'
      };

      const response = await request(app)
        .post('/api/terminals/spawn')
        .send(terminalConfig)
        .expect(201);

      expect(response.body).toMatchObject({
        id: expect.any(String),
        name: terminalConfig.name,
        command: terminalConfig.command,
        createdAt: expect.any(String)
      });
    });

    it('should validate terminal configuration', async () => {
      const invalidConfig = {
        name: '', // Invalid empty name
        command: null // Invalid command
      };

      const response = await request(app)
        .post('/api/terminals/spawn')
        .send(invalidConfig)
        .expect(400);

      expect(response.body.error).toBeDefined();
    });
  });

  describe('DELETE /api/terminals/:id', () => {
    it('should close terminal session', async () => {
      // Create terminal first
      const createResponse = await request(app)
        .post('/api/terminals/spawn')
        .send({ name: 'Test', command: '/bin/bash' });

      const terminalId = createResponse.body.id;

      // Delete terminal
      await request(app)
        .delete(`/api/terminals/${terminalId}`)
        .expect(200);

      // Verify terminal is deleted
      const listResponse = await request(app)
        .get('/api/terminals')
        .expect(200);

      const terminal = listResponse.body.find(t => t.id === terminalId);
      expect(terminal).toBeUndefined();
    });

    it('should return 404 for non-existent terminal', async () => {
      await request(app)
        .delete('/api/terminals/non-existent-id')
        .expect(404);
    });
  });
});
```

#### Configuration API
```javascript
// tests/integration/api/config.test.js
describe('Configuration API', () => {
  describe('GET /api/terminal-config', () => {
    it('should return default terminal configuration', async () => {
      const response = await request(app)
        .get('/api/terminal-config')
        .expect(200);

      expect(response.body).toMatchObject({
        cols: expect.any(Number),
        rows: expect.any(Number),
        theme: expect.any(Object),
        sessionId: null,
        timestamp: expect.any(Number)
      });
    });
  });

  describe('GET /api/terminal-config/:sessionId', () => {
    it('should return session-specific configuration', async () => {
      const sessionId = 'test-session-123';

      const response = await request(app)
        .get(`/api/terminal-config/${sessionId}`)
        .expect(200);

      expect(response.body.sessionId).toBe(sessionId);
    });
  });
});
```

## WebSocket Testing Strategy

### Connection Management Testing
```javascript
// tests/integration/websocket/connection.test.js
describe('WebSocket Connection Management', () => {
  let server, client;

  beforeEach(async () => {
    server = await startTestServer();
    client = await createWebSocketClient();
  });

  afterEach(async () => {
    await client.disconnect();
    await server.close();
  });

  it('should establish WebSocket connection', async () => {
    expect(client.connected).toBe(true);

    // Should receive initial configuration
    const configMessage = await waitForMessage(client, 'terminal-config');
    expect(configMessage.cols).toBeGreaterThan(0);
    expect(configMessage.rows).toBeGreaterThan(0);
  });

  it('should handle connection interruption and reconnection', async () => {
    // Simulate network interruption
    client.disconnect();

    // Reconnect
    await client.connect();

    expect(client.connected).toBe(true);
  });

  it('should manage multiple concurrent connections', async () => {
    const clients = await Promise.all([
      createWebSocketClient(),
      createWebSocketClient(),
      createWebSocketClient()
    ]);

    for (const client of clients) {
      expect(client.connected).toBe(true);
    }

    // Cleanup
    for (const client of clients) {
      await client.disconnect();
    }
  });
});
```

### Terminal Data Flow Testing
```javascript
// tests/integration/websocket/dataflow.test.js
describe('WebSocket Terminal Data Flow', () => {
  let server, client;

  beforeEach(async () => {
    server = await startTestServer();
    client = await createWebSocketClient();
  });

  it('should handle terminal input and output', async () => {
    // Send terminal input
    client.emit('data', {
      sessionId: 'test-session',
      data: 'echo "Hello World"'
    });

    // Wait for terminal output
    const outputMessage = await waitForMessage(client, 'terminal-data');
    expect(outputMessage.data).toContain('Hello World');
  });

  it('should handle ANSI escape sequences', async () => {
    const ansiInput = '\x1b[31mRed Text\x1b[0m';

    client.emit('data', {
      sessionId: 'test-session',
      data: `echo -e "${ansiInput}"`
    });

    const outputMessage = await waitForMessage(client, 'terminal-data');
    expect(outputMessage.data).toContain(ansiInput);
  });

  it('should handle large data payloads', async () => {
    const largePayload = 'x'.repeat(100000); // 100KB

    client.emit('data', {
      sessionId: 'test-session',
      data: largePayload
    });

    const outputMessage = await waitForMessage(client, 'terminal-data');
    expect(outputMessage.data).toBe(largePayload);
  });

  it('should handle terminal resize events', async () => {
    const resizeParams = { cols: 132, rows: 43 };

    client.emit('resize', {
      sessionId: 'test-session',
      ...resizeParams
    });

    // Should not produce errors and terminal should be resized
    const errorMessage = await waitForMessage(client, 'terminal-error', 1000, false);
    expect(errorMessage).toBeNull();
  });
});
```

### Session Management Testing
```javascript
// tests/integration/websocket/sessions.test.js
describe('WebSocket Session Management', () => {
  it('should handle session creation', async () => {
    const client = await createWebSocketClient();

    client.emit('create');

    const sessionMessage = await waitForMessage(client, 'session-created');
    expect(sessionMessage.sessionId).toBeDefined();

    await client.disconnect();
  });

  it('should handle session switching', async () => {
    const client = await createWebSocketClient();

    // Create two sessions
    client.emit('create');
    const session1 = await waitForMessage(client, 'session-created');

    client.emit('create');
    const session2 = await waitForMessage(client, 'session-created');

    // Switch between sessions
    client.emit('switch-session', { targetSessionId: session1.sessionId });

    const switchMessage = await waitForMessage(client, 'session-switched');
    expect(switchMessage.sessionId).toBe(session1.sessionId);
    expect(switchMessage.success).toBe(true);

    await client.disconnect();
  });

  it('should handle session cleanup on disconnect', async () => {
    const client = await createWebSocketClient();

    // Create session
    client.emit('create');
    const session = await waitForMessage(client, 'session-created');

    // Disconnect client
    await client.disconnect();

    // Session should be cleaned up (test via server-side validation)
    const serverClient = await createWebSocketClient();

    serverClient.emit('list');
    const sessionList = await waitForMessage(serverClient, 'session-list');

    const existingSession = sessionList.sessions.find(s => s.id === session.sessionId);
    expect(existingSession).toBeUndefined();

    await serverClient.disconnect();
  });
});
```

## Coverage Requirements and Quality Gates

### Coverage Thresholds by Layer
```javascript
// jest.config.js coverage configuration
coverageThreshold: {
  global: {
    branches: 75,
    functions: 80,
    lines: 80,
    statements: 80
  },

  // Higher standards for critical components
  "src/lib/tmux-stream-manager.js": {
    branches: 90,
    functions: 95,
    lines: 95,
    statements: 95
  },

  "src/lib/websocket-manager.js": {
    branches: 85,
    functions: 90,
    lines: 90,
    statements: 90
  },

  // Utilities should be thoroughly tested
  "src/utils/": {
    branches: 85,
    functions: 90,
    lines: 90,
    statements: 90
  },

  // API endpoints
  "unified-server.js": {
    branches: 80,
    functions: 85,
    lines: 85,
    statements: 85
  }
}
```

### Quality Gates for CI/CD
```yaml
# Quality gate configuration
quality-gates:
  test-coverage:
    minimum: 80%
    fail-on-decrease: true

  performance:
    websocket-latency: <100ms
    api-response-time: <200ms
    concurrent-connections: >100

  security:
    vulnerability-scan: pass
    dependency-audit: pass

  reliability:
    test-success-rate: >95%
    flaky-test-tolerance: <5%
```

## Monitoring and Alerting

### Test Metrics Collection
```javascript
// tests/utils/metricsCollector.js
export class TestMetricsCollector {
  static async collectMetrics() {
    return {
      testExecution: {
        totalTests: await this.getTotalTestCount(),
        passedTests: await this.getPassedTestCount(),
        failedTests: await this.getFailedTestCount(),
        skippedTests: await this.getSkippedTestCount(),
        executionTime: await this.getExecutionTime(),
        coverage: await this.getCoverageMetrics()
      },

      performance: {
        websocketLatency: await this.measureWebSocketLatency(),
        apiResponseTime: await this.measureAPIResponseTime(),
        concurrentConnections: await this.measureConcurrentConnections()
      },

      reliability: {
        flakyTests: await this.identifyFlakyTests(),
        failureRate: await this.calculateFailureRate(),
        recoveryTime: await this.measureRecoveryTime()
      }
    };
  }
}
```

### Alerting Configuration
```javascript
// Integration with monitoring systems
const alertingConfig = {
  testFailures: {
    threshold: 5, // Alert if >5% of tests fail
    channels: ['slack', 'email'],
    escalation: 'oncall'
  },

  coverageDrops: {
    threshold: 75, // Alert if coverage drops below 75%
    channels: ['slack'],
    escalation: 'team-lead'
  },

  performanceDegradation: {
    websocketLatency: {
      threshold: 500, // Alert if latency >500ms
      channels: ['slack'],
      escalation: 'performance-team'
    }
  }
};
```

## Best Practices and Guidelines

### Test Writing Standards
1. **AAA Pattern:** Arrange, Act, Assert structure
2. **Single Responsibility:** One test per behavior
3. **Descriptive Names:** Clear test and assertion names
4. **Data Independence:** Tests should not depend on external data
5. **Fast Execution:** Unit tests should run in <1s, integration tests <10s

### Mock Strategy Guidelines
1. **Mock External Dependencies:** APIs, databases, file systems
2. **Preserve Behavior:** Mocks should match real implementation behavior
3. **Stub vs Mock:** Use stubs for queries, mocks for commands
4. **Shared Mocks:** Reuse common mocks across test suites

### Performance Testing Guidelines
1. **Baseline Establishment:** Measure current performance before optimization
2. **Realistic Load:** Test with production-like data volumes
3. **Gradual Ramp-up:** Increase load gradually to identify breaking points
4. **Resource Monitoring:** Track CPU, memory, network during tests

### Security Testing Guidelines
1. **Input Validation:** Test all input boundaries and edge cases
2. **Authentication:** Verify all authentication mechanisms
3. **Authorization:** Test role-based access controls
4. **Data Sanitization:** Ensure all user input is properly sanitized

## Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
- Set up Jest configuration with coverage
- Implement basic unit test structure
- Create mock utilities and helpers
- Set up CI/CD integration

### Phase 2: Core Testing (Weeks 3-4)
- Implement API endpoint integration tests
- Create WebSocket connection tests
- Set up terminal interaction testing
- Implement basic E2E workflows

### Phase 3: Advanced Testing (Weeks 5-6)
- Performance testing with k6
- Security testing implementation
- Cross-browser E2E testing
- Load and stress testing

### Phase 4: Optimization (Weeks 7-8)
- Parallel test execution optimization
- Test reporting and dashboards
- Performance monitoring integration
- Documentation and training

## Conclusion

This test architecture provides a comprehensive framework for ensuring the reliability, performance, and security of the claude-flow-ui application. The multi-layered approach ensures coverage across all system components while maintaining efficient test execution and clear quality gates.

The architecture emphasizes:
- **Comprehensive Coverage:** All system layers from unit to security testing
- **Performance Focus:** Real-time WebSocket and terminal performance validation
- **Security First:** Proactive security testing and vulnerability detection
- **CI/CD Integration:** Automated testing pipeline with quality gates
- **Maintainability:** Clear organization, naming conventions, and documentation

Regular review and updates of this architecture ensure it evolves with the application and maintains testing effectiveness as the system grows.