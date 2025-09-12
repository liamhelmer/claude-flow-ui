# Mock Strategy Guide

## Overview
This guide provides comprehensive strategies for mocking external dependencies in the Claude UI project to ensure reliable, fast, and deterministic tests.

## Mock Hierarchy and Strategy

### 1. Browser APIs
Browser APIs are mocked globally to ensure tests run consistently across environments.

#### WebSocket Mocking
```typescript
// Global WebSocket mock in tests/setup.ts
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  url: string;
  onopen: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    }, 0);
  }

  send(data: string | Buffer) {
    // Track sent messages for testing
  }

  close(code?: number, reason?: string) {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code, reason }));
    }
  }
}

global.WebSocket = MockWebSocket;
```

#### Canvas and Rendering Mocks
```typescript
// Canvas context mock for xterm.js
const mockCanvasContext = {
  fillRect: jest.fn(),
  clearRect: jest.fn(),
  getImageData: jest.fn(() => ({ data: new Uint8ClampedArray(4) })),
  putImageData: jest.fn(),
  createImageData: jest.fn(() => ({ data: new Uint8ClampedArray(4) })),
  setTransform: jest.fn(),
  drawImage: jest.fn(),
  save: jest.fn(),
  restore: jest.fn(),
  fillText: jest.fn(),
  strokeText: jest.fn(),
  measureText: jest.fn(() => ({ width: 10, height: 12 })),
  // ... other canvas methods
};

HTMLCanvasElement.prototype.getContext = jest.fn(() => mockCanvasContext);
```

#### Observer APIs
```typescript
// ResizeObserver mock for responsive components
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// IntersectionObserver mock for lazy loading
global.IntersectionObserver = class IntersectionObserver {
  constructor(callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {}
  observe(target: Element): void {}
  unobserve(target: Element): void {}
  disconnect(): void {}
  takeRecords(): IntersectionObserverEntry[] { return []; }
};
```

#### Media Queries
```typescript
// matchMedia mock for responsive design
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});
```

### 2. Third-Party Library Mocks

#### Next.js Framework Mocks
```typescript
// Next.js router mock
jest.mock('next/router', () => ({
  useRouter() {
    return {
      route: '/',
      pathname: '/',
      query: {},
      asPath: '/',
      push: jest.fn(),
      pop: jest.fn(),
      reload: jest.fn(),
      back: jest.fn(),
      forward: jest.fn(),
      prefetch: jest.fn().mockResolvedValue(undefined),
      beforePopState: jest.fn(),
      events: {
        on: jest.fn(),
        off: jest.fn(),
        emit: jest.fn(),
      },
      isFallback: false,
      isLocaleDomain: true,
      isReady: true,
      defaultLocale: 'en',
      domainLocales: [],
      isPreview: false,
    };
  },
}));

// Next.js dynamic imports mock
jest.mock('next/dynamic', () => {
  const mockDynamic = (fn: () => any, options?: any) => {
    const Component = (props: any) => {
      if (options?.loading) {
        return React.createElement(options.loading);
      }
      
      try {
        const DynamicComponent = fn();
        
        if (typeof DynamicComponent?.then === 'function') {
          return React.createElement('div', { 'data-testid': 'loading-dynamic' }, 'Loading...');
        }
        
        const ComponentToRender = DynamicComponent?.default || DynamicComponent;
        
        if (typeof ComponentToRender === 'function') {
          return React.createElement(ComponentToRender, props);
        }
        
        return React.createElement('div', { 'data-testid': 'mock-component', ...props });
      } catch (error) {
        return React.createElement('div', { 'data-testid': 'error-dynamic' }, 'Component Error');
      }
    };
    
    Component.displayName = 'MockedDynamicComponent';
    return Component;
  };
  
  return mockDynamic;
});
```

#### XTerm.js Terminal Mock
```typescript
// Terminal library mock
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => ({
    open: jest.fn(),
    write: jest.fn(),
    writeln: jest.fn(),
    clear: jest.fn(),
    reset: jest.fn(),
    focus: jest.fn(),
    blur: jest.fn(),
    scrollToBottom: jest.fn(),
    scrollToTop: jest.fn(),
    dispose: jest.fn(),
    onData: jest.fn(),
    onResize: jest.fn(),
    onKey: jest.fn(),
    onTitleChange: jest.fn(),
    loadAddon: jest.fn(),
    cols: 80,
    rows: 24,
    element: document.createElement('div'),
  })),
}));

jest.mock('@xterm/addon-fit', () => ({
  FitAddon: jest.fn().mockImplementation(() => ({
    fit: jest.fn(),
    proposeDimensions: jest.fn(() => ({ cols: 80, rows: 24 })),
    activate: jest.fn(),
    dispose: jest.fn(),
  })),
}));
```

#### Socket.IO Mock
```typescript
// Socket.IO client mock
jest.mock('socket.io-client', () => {
  const mockSocket = {
    id: 'mock-socket-id',
    connected: true,
    disconnected: false,
    on: jest.fn(),
    off: jest.fn(),
    emit: jest.fn(),
    connect: jest.fn(),
    disconnect: jest.fn(),
    removeAllListeners: jest.fn(),
  };
  
  return {
    io: jest.fn(() => mockSocket),
    Socket: jest.fn(() => mockSocket),
  };
});
```

#### Node-PTY (Server-side)
```typescript
// Node-pty mock for server-side tests
jest.mock('node-pty', () => ({
  spawn: jest.fn(() => ({
    pid: 12345,
    onData: jest.fn(),
    onExit: jest.fn(),
    write: jest.fn(),
    resize: jest.fn(),
    kill: jest.fn(),
  })),
}));
```

### 3. Mock Factories and Builders

#### Test Data Factories
```typescript
// factories/session.factory.ts
export interface SessionFactory {
  build(): TerminalSession;
  withId(id: string): SessionFactory;
  withName(name: string): SessionFactory;
  active(): SessionFactory;
  inactive(): SessionFactory;
  withHistory(history: string[]): SessionFactory;
  withLastActivity(date: Date): SessionFactory;
}

export const createSessionFactory = (): SessionFactory => {
  let overrides: Partial<TerminalSession> = {};

  const factory: SessionFactory = {
    build(): TerminalSession {
      return {
        id: faker.string.uuid(),
        name: faker.internet.domainWord(),
        isActive: false,
        lastActivity: faker.date.recent().toISOString(),
        history: [],
        ...overrides,
      };
    },

    withId(id: string): SessionFactory {
      overrides.id = id;
      return factory;
    },

    withName(name: string): SessionFactory {
      overrides.name = name;
      return factory;
    },

    active(): SessionFactory {
      overrides.isActive = true;
      return factory;
    },

    inactive(): SessionFactory {
      overrides.isActive = false;
      return factory;
    },

    withHistory(history: string[]): SessionFactory {
      overrides.history = history;
      return factory;
    },

    withLastActivity(date: Date): SessionFactory {
      overrides.lastActivity = date.toISOString();
      return factory;
    },
  };

  return factory;
};

// Usage example
const activeSession = createSessionFactory()
  .withId('test-session-1')
  .withName('Test Terminal')
  .active()
  .withHistory(['ls -la', 'pwd', 'npm test'])
  .build();
```

#### WebSocket Message Factory
```typescript
// factories/websocket.factory.ts
export interface WebSocketMessageFactory {
  build(): WebSocketMessage;
  withType(type: string): WebSocketMessageFactory;
  withSessionId(sessionId: string): WebSocketMessageFactory;
  withData(data: any): WebSocketMessageFactory;
  terminalData(): WebSocketMessageFactory;
  systemMessage(): WebSocketMessageFactory;
  errorMessage(): WebSocketMessageFactory;
}

export const createWebSocketMessageFactory = (): WebSocketMessageFactory => {
  let overrides: Partial<WebSocketMessage> = {};

  const factory: WebSocketMessageFactory = {
    build(): WebSocketMessage {
      return {
        type: 'terminal-data',
        sessionId: faker.string.uuid(),
        data: faker.lorem.sentence(),
        timestamp: Date.now(),
        ...overrides,
      };
    },

    withType(type: string): WebSocketMessageFactory {
      overrides.type = type;
      return factory;
    },

    withSessionId(sessionId: string): WebSocketMessageFactory {
      overrides.sessionId = sessionId;
      return factory;
    },

    withData(data: any): WebSocketMessageFactory {
      overrides.data = data;
      return factory;
    },

    terminalData(): WebSocketMessageFactory {
      overrides.type = 'terminal-data';
      overrides.data = faker.system.filePath() + '\r\n$ ';
      return factory;
    },

    systemMessage(): WebSocketMessageFactory {
      overrides.type = 'system';
      overrides.data = {
        level: 'info',
        message: faker.lorem.sentence(),
      };
      return factory;
    },

    errorMessage(): WebSocketMessageFactory {
      overrides.type = 'error';
      overrides.data = {
        code: faker.number.int({ min: 400, max: 599 }),
        message: faker.lorem.sentence(),
      };
      return factory;
    },
  };

  return factory;
};
```

#### System Metrics Factory
```typescript
// factories/metrics.factory.ts
export interface MetricsFactory {
  build(): SystemMetrics;
  withMemoryUsage(percentage: number): MetricsFactory;
  withCpuLoad(load: number[]): MetricsFactory;
  withHighMemory(): MetricsFactory;
  withLowMemory(): MetricsFactory;
  withHighCpu(): MetricsFactory;
  withLowCpu(): MetricsFactory;
}

export const createMetricsFactory = (): MetricsFactory => {
  let overrides: Partial<SystemMetrics> = {};

  const factory: MetricsFactory = {
    build(): SystemMetrics {
      return {
        memoryTotal: 17179869184, // 16GB
        memoryUsed: faker.number.int({ min: 1000000000, max: 15000000000 }),
        memoryFree: 0, // Calculated
        memoryUsagePercent: 0, // Calculated
        memoryEfficiency: faker.number.float({ min: 10, max: 30 }),
        cpuCount: faker.number.int({ min: 4, max: 16 }),
        cpuLoad: [
          faker.number.float({ min: 0, max: 2 }),
          faker.number.float({ min: 0, max: 2 }),
          faker.number.float({ min: 0, max: 2 }),
        ],
        platform: faker.helpers.arrayElement(['darwin', 'linux', 'win32']),
        uptime: faker.number.int({ min: 0, max: 604800 }), // Up to a week
        timestamp: Date.now(),
        ...overrides,
      };
    },

    withMemoryUsage(percentage: number): MetricsFactory {
      const total = 17179869184;
      overrides.memoryUsed = Math.floor(total * (percentage / 100));
      overrides.memoryFree = total - overrides.memoryUsed;
      overrides.memoryUsagePercent = percentage;
      return factory;
    },

    withCpuLoad(load: number[]): MetricsFactory {
      overrides.cpuLoad = load;
      return factory;
    },

    withHighMemory(): MetricsFactory {
      return factory.withMemoryUsage(faker.number.int({ min: 80, max: 95 }));
    },

    withLowMemory(): MetricsFactory {
      return factory.withMemoryUsage(faker.number.int({ min: 10, max: 30 }));
    },

    withHighCpu(): MetricsFactory {
      overrides.cpuLoad = [
        faker.number.float({ min: 1.5, max: 3 }),
        faker.number.float({ min: 1.5, max: 3 }),
        faker.number.float({ min: 1.5, max: 3 }),
      ];
      return factory;
    },

    withLowCpu(): MetricsFactory {
      overrides.cpuLoad = [
        faker.number.float({ min: 0, max: 0.5 }),
        faker.number.float({ min: 0, max: 0.5 }),
        faker.number.float({ min: 0, max: 0.5 }),
      ];
      return factory;
    },
  };

  return factory;
};
```

### 4. Mock Utilities and Helpers

#### Mock WebSocket Client
```typescript
// utils/mockWebSocketClient.ts
export interface MockWebSocketClient {
  connected: boolean;
  connecting: boolean;
  on: jest.MockedFunction<any>;
  off: jest.MockedFunction<any>;
  emit: jest.MockedFunction<any>;
  connect: jest.MockedFunction<any>;
  disconnect: jest.MockedFunction<any>;
  send: jest.MockedFunction<any>;
  simulateMessage: (type: string, data: any) => void;
  simulateConnection: () => void;
  simulateDisconnection: (reason?: string) => void;
  simulateError: (error: Error) => void;
}

export const createMockWebSocketClient = (): MockWebSocketClient => {
  const listeners: { [event: string]: Function[] } = {};

  const client: MockWebSocketClient = {
    connected: false,
    connecting: false,
    on: jest.fn((event: string, callback: Function) => {
      if (!listeners[event]) {
        listeners[event] = [];
      }
      listeners[event].push(callback);
    }),
    off: jest.fn((event: string, callback?: Function) => {
      if (listeners[event]) {
        if (callback) {
          listeners[event] = listeners[event].filter(cb => cb !== callback);
        } else {
          listeners[event] = [];
        }
      }
    }),
    emit: jest.fn((event: string, ...args: any[]) => {
      if (listeners[event]) {
        listeners[event].forEach(callback => callback(...args));
      }
    }),
    connect: jest.fn(() => {
      client.connecting = true;
      setTimeout(() => {
        client.connecting = false;
        client.connected = true;
        client.emit('connect');
      }, 0);
    }),
    disconnect: jest.fn(() => {
      client.connected = false;
      client.emit('disconnect');
    }),
    send: jest.fn(),

    simulateMessage(type: string, data: any) {
      client.emit(type, data);
    },

    simulateConnection() {
      client.connected = true;
      client.connecting = false;
      client.emit('connect');
    },

    simulateDisconnection(reason = 'manual') {
      client.connected = false;
      client.emit('disconnect', reason);
    },

    simulateError(error: Error) {
      client.emit('error', error);
    },
  };

  return client;
};
```

#### Mock Store
```typescript
// utils/mockStore.ts
export interface MockStoreState {
  sessions: TerminalSession[];
  activeSessionId: string | null;
  metrics: SystemMetrics;
  agents: AgentStatus[];
}

export const createMockStore = (initialState?: Partial<MockStoreState>) => {
  const defaultState: MockStoreState = {
    sessions: [],
    activeSessionId: null,
    metrics: createMetricsFactory().build(),
    agents: [],
    ...initialState,
  };

  let state = { ...defaultState };
  const listeners: Function[] = [];

  return {
    getState: () => state,
    setState: (newState: Partial<MockStoreState>) => {
      state = { ...state, ...newState };
      listeners.forEach(listener => listener(state));
    },
    subscribe: (listener: Function) => {
      listeners.push(listener);
      return () => {
        const index = listeners.indexOf(listener);
        if (index > -1) {
          listeners.splice(index, 1);
        }
      };
    },
    reset: () => {
      state = { ...defaultState };
    },
  };
};
```

### 5. Mock Strategies by Test Type

#### Unit Test Mocks
For unit tests, use minimal, focused mocks:

```typescript
// Minimal component mock
const mockTerminal = {
  write: jest.fn(),
  onData: jest.fn(),
  focus: jest.fn(),
};

// Minimal hook mock
const mockUseTerminal = {
  terminal: mockTerminal,
  connected: true,
  send: jest.fn(),
};
```

#### Integration Test Mocks
For integration tests, use more comprehensive mocks that simulate real interactions:

```typescript
// Comprehensive WebSocket mock for integration tests
const createIntegrationWebSocketMock = () => {
  const mock = createMockWebSocketClient();
  
  // Add realistic behaviors
  mock.connect.mockImplementation(() => {
    mock.connecting = true;
    setTimeout(() => {
      mock.connecting = false;
      mock.connected = true;
      mock.emit('connect');
    }, 100); // Simulate network delay
  });

  mock.send.mockImplementation((data) => {
    // Echo back after delay to simulate server processing
    setTimeout(() => {
      mock.emit('terminal-data', {
        sessionId: 'test-session',
        data: `Echo: ${data}\r\n$ `,
      });
    }, 50);
  });

  return mock;
};
```

#### End-to-End Test Mocks
For E2E tests, use mocks that closely mimic production behavior:

```typescript
// Production-like mocks for E2E tests
const createE2EMocks = () => {
  return {
    webSocket: createRealisticWebSocketMock(),
    terminal: createRealisticTerminalMock(),
    metrics: createStreamingMetricsMock(),
  };
};

const createRealisticWebSocketMock = () => {
  const mock = createMockWebSocketClient();
  
  // Simulate network issues
  let connectionAttempts = 0;
  mock.connect.mockImplementation(() => {
    connectionAttempts++;
    if (connectionAttempts === 1) {
      // First attempt fails
      setTimeout(() => mock.emit('error', new Error('Connection failed')), 100);
    } else {
      // Second attempt succeeds
      setTimeout(() => {
        mock.connected = true;
        mock.emit('connect');
      }, 200);
    }
  });

  return mock;
};
```

### 6. Mock Cleanup and Memory Management

#### Automatic Mock Cleanup
```typescript
// tests/utils/mockCleanup.ts
export const setupMockCleanup = () => {
  beforeEach(() => {
    // Reset all mocks to clean state
    jest.clearAllMocks();
    
    // Reset global mock state
    global.testUtils.mockLocalStorage();
    global.testUtils.mockSessionStorage();
    
    // Reset WebSocket mock state
    if (global.WebSocket) {
      global.WebSocket.prototype.readyState = WebSocket.CONNECTING;
    }
  });

  afterEach(() => {
    // Clean up any hanging timers
    jest.clearAllTimers();
    
    // Clean up event listeners
    document.body.innerHTML = '';
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });

  afterAll(() => {
    // Restore original implementations
    jest.restoreAllMocks();
  });
};
```

#### Memory Leak Prevention
```typescript
// tests/utils/memoryLeakPrevention.ts
export const preventMemoryLeaks = () => {
  let initialMemory: number;

  beforeEach(() => {
    if (performance.memory) {
      initialMemory = performance.memory.usedJSHeapSize;
    }
  });

  afterEach(() => {
    // Check for memory leaks
    if (performance.memory && initialMemory) {
      const currentMemory = performance.memory.usedJSHeapSize;
      const memoryIncrease = currentMemory - initialMemory;
      const memoryIncreasePercentage = (memoryIncrease / initialMemory) * 100;

      if (memoryIncreasePercentage > 50) {
        console.warn(`Potential memory leak detected: ${memoryIncreasePercentage.toFixed(2)}% increase`);
      }
    }

    // Clean up DOM
    document.body.innerHTML = '';
    
    // Clear any intervals/timeouts
    const highestId = setTimeout(() => {}, 0);
    for (let i = 0; i < highestId; i++) {
      clearTimeout(i);
      clearInterval(i);
    }
  });
};
```

### 7. Advanced Mock Patterns

#### Partial Mocking
```typescript
// Mock only specific methods while preserving others
jest.mock('../utils', () => ({
  ...jest.requireActual('../utils'),
  formatBytes: jest.fn(),
}));
```

#### Conditional Mocking
```typescript
// Mock based on test environment
const shouldMockWebSocket = process.env.NODE_ENV === 'test';

if (shouldMockWebSocket) {
  jest.mock('socket.io-client', () => mockSocketIO);
}
```

#### Spy on Real Implementation
```typescript
// Spy on real methods for behavior verification
const realUtils = jest.requireActual('../utils');
const spyFormatBytes = jest.spyOn(realUtils, 'formatBytes');

// Use real implementation but track calls
expect(spyFormatBytes).toHaveBeenCalledWith(1024);
```

### 8. Mock Validation and Testing

#### Mock Assertion Helpers
```typescript
// tests/utils/mockAssertions.ts
export const expectWebSocketMessage = (
  mockClient: MockWebSocketClient,
  type: string,
  data?: any
) => {
  expect(mockClient.emit).toHaveBeenCalledWith(
    type,
    data ? expect.objectContaining(data) : expect.anything()
  );
};

export const expectTerminalWrite = (
  mockTerminal: any,
  expectedText: string | RegExp
) => {
  if (typeof expectedText === 'string') {
    expect(mockTerminal.write).toHaveBeenCalledWith(
      expect.stringContaining(expectedText)
    );
  } else {
    expect(mockTerminal.write).toHaveBeenCalledWith(
      expect.stringMatching(expectedText)
    );
  }
};
```

#### Mock State Validation
```typescript
// Validate mock state consistency
export const validateMockState = (mockClient: MockWebSocketClient) => {
  // Ensure mock state is consistent
  if (mockClient.connected) {
    expect(mockClient.connecting).toBe(false);
  }
  
  if (mockClient.connecting) {
    expect(mockClient.connected).toBe(false);
  }
};
```

## Best Practices

### 1. Mock Naming Conventions
- Use `Mock` prefix for mock classes: `MockWebSocket`
- Use `mock` prefix for mock instances: `mockClient`
- Use `create` prefix for factory functions: `createMockSession`

### 2. Mock Scope
- **Global mocks**: For browser APIs and core libraries
- **Module mocks**: For third-party packages
- **Local mocks**: For specific test scenarios

### 3. Mock Fidelity
- **Unit tests**: Minimal mocks focused on the unit under test
- **Integration tests**: More realistic mocks that simulate interactions
- **E2E tests**: High-fidelity mocks that closely mimic production

### 4. Mock Maintenance
- Keep mocks simple and focused
- Update mocks when APIs change
- Remove unused mocks regularly
- Document complex mock behaviors

### 5. Performance Considerations
- Avoid heavy computations in mocks
- Use lazy initialization for expensive mocks
- Clean up mocks properly to prevent memory leaks
- Profile tests to identify slow mocks

## Troubleshooting Common Mock Issues

### 1. Mock Not Applied
```typescript
// ❌ Wrong: Mock after import
import { useWebSocket } from './hooks';
jest.mock('./hooks');

// ✅ Correct: Mock before import
jest.mock('./hooks');
import { useWebSocket } from './hooks';
```

### 2. Mock State Pollution
```typescript
// ❌ Wrong: Shared mock state
const mockClient = createMockWebSocketClient();

// ✅ Correct: Fresh mock for each test
beforeEach(() => {
  mockClient = createMockWebSocketClient();
});
```

### 3. Async Mock Timing
```typescript
// ❌ Wrong: Not waiting for async mock
mockClient.connect();
expect(mockClient.connected).toBe(true); // Fails

// ✅ Correct: Wait for async behavior
mockClient.connect();
await waitFor(() => {
  expect(mockClient.connected).toBe(true);
});
```

## Conclusion

Effective mocking is crucial for reliable, fast, and maintainable tests. This guide provides a comprehensive foundation for implementing consistent mocking strategies across the Claude UI project. Regular review and updates of mock implementations will ensure they continue to serve the project's testing needs effectively.