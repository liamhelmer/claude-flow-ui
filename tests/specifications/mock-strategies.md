# Mock Strategies & Test Utilities
## Claude Flow UI Testing Infrastructure

### 🎯 Overview
Comprehensive mocking strategies for isolating components and testing different scenarios without external dependencies.

---

## 🔌 WebSocket Mocking

### Enhanced WebSocket Client Mock

```typescript
// tests/mocks/MockWebSocketClient.ts
export class MockWebSocketClient {
  public connected: boolean = false;
  public connecting: boolean = false;
  private eventListeners: Map<string, Function[]> = new Map();
  private messageHistory: WebSocketMessage[] = [];
  private connectionDelay: number = 0;
  private shouldFailConnection: boolean = false;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;

  constructor(options?: {
    connectionDelay?: number;
    shouldFailConnection?: boolean;
    maxReconnectAttempts?: number;
  }) {
    this.connectionDelay = options?.connectionDelay || 0;
    this.shouldFailConnection = options?.shouldFailConnection || false;
    this.maxReconnectAttempts = options?.maxReconnectAttempts || 5;
  }

  async connect(): Promise<void> {
    this.connecting = true;
    
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (this.shouldFailConnection) {
          this.connecting = false;
          reject(new Error('Mock connection failed'));
          return;
        }

        this.connected = true;
        this.connecting = false;
        this.emit('connect', {});
        resolve();
      }, this.connectionDelay);
    });
  }

  disconnect(): void {
    this.connected = false;
    this.connecting = false;
    this.eventListeners.clear();
    this.emit('disconnect', { reason: 'manual' });
  }

  send(event: string, data: any): void {
    if (!this.connected) {
      throw new Error('WebSocket not connected');
    }
    
    const message: WebSocketMessage = {
      type: event as any,
      data,
      timestamp: Date.now()
    };
    
    this.messageHistory.push(message);
    
    // Echo back certain messages for testing
    this.handleMockServerResponse(event, data);
  }

  on(event: string, callback: Function): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event)!.push(callback);
  }

  off(event: string, callback: Function): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      const index = listeners.indexOf(callback);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  private emit(event: string, data: any): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.forEach(callback => callback(data));
    }
  }

  private handleMockServerResponse(event: string, data: any): void {
    setTimeout(() => {
      switch (event) {
        case 'create':
          this.emit('session-created', {
            sessionId: `mock-session-${Date.now()}`,
            ...data
          });
          break;
        
        case 'destroy':
          this.emit('session-destroyed', {
            sessionId: data.sessionId,
            reason: 'manual'
          });
          break;
        
        case 'data':
          this.emit('terminal-data', {
            sessionId: data.sessionId,
            data: `Echo: ${data.data}`
          });
          break;
        
        case 'resize':
          this.emit('terminal-config', {
            sessionId: data.sessionId,
            cols: data.cols,
            rows: data.rows
          });
          break;
      }
    }, 10);
  }

  // Test utilities
  simulateServerMessage(event: string, data: any): void {
    setTimeout(() => this.emit(event, data), 0);
  }

  simulateConnectionError(error: Error = new Error('Connection failed')): void {
    this.connected = false;
    this.connecting = false;
    this.emit('connect_error', error);
  }

  simulateDisconnection(reason: string = 'transport close'): void {
    this.connected = false;
    this.emit('disconnect', { reason });
  }

  simulateReconnection(): Promise<void> {
    this.reconnectAttempts++;
    if (this.reconnectAttempts > this.maxReconnectAttempts) {
      return Promise.reject(new Error('Max reconnection attempts exceeded'));
    }
    
    return this.connect();
  }

  getMessageHistory(): WebSocketMessage[] {
    return [...this.messageHistory];
  }

  clearMessageHistory(): void {
    this.messageHistory = [];
  }

  getListenerCount(event: string): number {
    return this.eventListeners.get(event)?.length || 0;
  }
}
```

### WebSocket Test Utilities

```typescript
// tests/utils/websocket-test-utils.ts
export const createWebSocketMock = (options?: {
  delayMs?: number;
  shouldFail?: boolean;
  responses?: Record<string, any>;
}) => {
  const mock = new MockWebSocketClient({
    connectionDelay: options?.delayMs || 0,
    shouldFailConnection: options?.shouldFail || false
  });

  // Setup custom responses
  if (options?.responses) {
    Object.entries(options.responses).forEach(([event, response]) => {
      mock.on(event, response);
    });
  }

  return mock;
};

export const waitForWebSocketEvent = (
  client: MockWebSocketClient,
  event: string,
  timeout = 1000
): Promise<any> => {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timeout waiting for event: ${event}`));
    }, timeout);

    client.on(event, (data) => {
      clearTimeout(timer);
      resolve(data);
    });
  });
};
```

---

## 🖥️ Terminal Backend Mocking

### Mock PTY Process

```typescript
// tests/mocks/MockTerminalBackend.ts
export class MockTerminalBackend {
  private sessions: Map<string, MockSession> = new Map();
  private nextSessionId: number = 1;

  createSession(options?: {
    shell?: string;
    cwd?: string;
    env?: Record<string, string>;
  }): Promise<SessionData> {
    return new Promise((resolve) => {
      const sessionId = `mock-session-${this.nextSessionId++}`;
      const session = new MockSession(sessionId, options);
      
      this.sessions.set(sessionId, session);
      
      resolve({
        sessionId,
        pid: Math.floor(Math.random() * 10000) + 1000,
        shell: options?.shell || '/bin/bash',
        cwd: options?.cwd || '/home/user',
        cols: 80,
        rows: 24
      });
    });
  }

  destroySession(sessionId: string): Promise<void> {
    return new Promise((resolve) => {
      const session = this.sessions.get(sessionId);
      if (session) {
        session.destroy();
        this.sessions.delete(sessionId);
      }
      resolve();
    });
  }

  sendData(sessionId: string, data: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.handleInput(data);
    }
  }

  resize(sessionId: string, cols: number, rows: number): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.resize(cols, rows);
    }
  }

  // Test utilities
  simulateOutput(sessionId: string, text: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.emitOutput(text);
    }
  }

  simulateExit(sessionId: string, code: number = 0): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.emitExit(code);
    }
  }

  simulateError(sessionId: string, error: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.emitError(error);
    }
  }

  getSession(sessionId: string): MockSession | undefined {
    return this.sessions.get(sessionId);
  }

  getAllSessions(): MockSession[] {
    return Array.from(this.sessions.values());
  }
}

class MockSession {
  private eventCallbacks: Map<string, Function[]> = new Map();
  private outputBuffer: string = '';
  private isDestroyed: boolean = false;

  constructor(
    public sessionId: string,
    private options?: {
      shell?: string;
      cwd?: string;
      env?: Record<string, string>;
    }
  ) {}

  handleInput(data: string): void {
    if (this.isDestroyed) return;

    // Echo input and simulate command processing
    this.emitOutput(data);
    
    // Simulate command responses
    if (data.includes('\r') || data.includes('\n')) {
      const command = this.outputBuffer.trim();
      this.processCommand(command);
      this.outputBuffer = '';
    } else {
      this.outputBuffer += data;
    }
  }

  private processCommand(command: string): void {
    setTimeout(() => {
      switch (true) {
        case command.startsWith('echo'):
          const text = command.slice(5);
          this.emitOutput(`${text}\r\n$ `);
          break;
        
        case command === 'ls':
          this.emitOutput('file1.txt  file2.js  directory/\r\n$ ');
          break;
        
        case command === 'pwd':
          this.emitOutput('/home/user\r\n$ ');
          break;
        
        case command === 'exit':
          this.emitExit(0);
          break;
        
        default:
          if (command) {
            this.emitOutput(`bash: ${command}: command not found\r\n$ `);
          } else {
            this.emitOutput('$ ');
          }
      }
    }, 50); // Simulate processing delay
  }

  resize(cols: number, rows: number): void {
    this.emit('resize', { sessionId: this.sessionId, cols, rows });
  }

  destroy(): void {
    this.isDestroyed = true;
    this.eventCallbacks.clear();
  }

  emitOutput(data: string): void {
    if (!this.isDestroyed) {
      this.emit('data', { sessionId: this.sessionId, data });
    }
  }

  emitExit(code: number): void {
    this.emit('exit', { sessionId: this.sessionId, exitCode: code });
    this.destroy();
  }

  emitError(error: string): void {
    this.emit('error', { sessionId: this.sessionId, error });
  }

  on(event: string, callback: Function): void {
    if (!this.eventCallbacks.has(event)) {
      this.eventCallbacks.set(event, []);
    }
    this.eventCallbacks.get(event)!.push(callback);
  }

  private emit(event: string, data: any): void {
    const callbacks = this.eventCallbacks.get(event);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }
}
```

---

## 🗃️ State Management Mocking

### Zustand Store Mocking

```typescript
// tests/mocks/MockAppStore.ts
import { StateCreator } from 'zustand';
import type { AppState } from '@/types';

export const createMockStore = (initialState?: Partial<AppState>) => {
  const defaultState: AppState = {
    terminalSessions: [],
    activeSessionId: null,
    sidebarOpen: true,
    loading: false,
    error: null,
  };

  return create<AppState & AppActions>()((set, get) => ({
    ...defaultState,
    ...initialState,

    // Mock implementations
    setSidebarOpen: jest.fn((open: boolean) =>
      set({ sidebarOpen: open })
    ),

    toggleSidebar: jest.fn(() =>
      set((state) => ({ sidebarOpen: !state.sidebarOpen }))
    ),

    setActiveSession: jest.fn((sessionId: string | null) =>
      set({ activeSessionId: sessionId })
    ),

    addSession: jest.fn((session: TerminalSession) =>
      set((state) => ({
        terminalSessions: [...state.terminalSessions, session],
      }))
    ),

    removeSession: jest.fn((sessionId: string) =>
      set((state) => {
        const newSessions = state.terminalSessions.filter(s => s.id !== sessionId);
        const newActiveId = 
          state.activeSessionId === sessionId 
            ? newSessions[0]?.id || null 
            : state.activeSessionId;
        
        return {
          terminalSessions: newSessions,
          activeSessionId: newActiveId,
        };
      })
    ),

    updateSession: jest.fn((sessionId: string, updates: Partial<TerminalSession>) =>
      set((state) => ({
        terminalSessions: state.terminalSessions.map((session) =>
          session.id === sessionId ? { ...session, ...updates } : session
        ),
      }))
    ),

    setLoading: jest.fn((loading: boolean) =>
      set({ loading })
    ),

    setError: jest.fn((error: string | null) =>
      set({ error })
    ),

    createNewSession: jest.fn(() => {
      const sessionId = `mock-session-${Date.now()}`;
      const newSession: TerminalSession = {
        id: sessionId,
        name: `Terminal ${get().terminalSessions.length + 1}`,
        isActive: true,
        lastActivity: new Date(),
      };

      set((state) => ({
        terminalSessions: [...state.terminalSessions, newSession],
        activeSessionId: sessionId,
      }));

      return sessionId;
    }),

    clearSessions: jest.fn(() =>
      set({ terminalSessions: [], activeSessionId: null })
    ),
  }));
};

// Store test utilities
export const createStoreWithSessions = (sessionCount: number = 3) => {
  const sessions: TerminalSession[] = Array.from({ length: sessionCount }, (_, i) => ({
    id: `session-${i + 1}`,
    name: `Terminal ${i + 1}`,
    isActive: i === 0,
    lastActivity: new Date(Date.now() - i * 1000),
  }));

  return createMockStore({
    terminalSessions: sessions,
    activeSessionId: sessions[0]?.id || null,
  });
};
```

---

## 🎨 Component Mocking

### React Component Mocks

```typescript
// tests/mocks/ComponentMocks.tsx
import React from 'react';

// Mock Terminal component
export const MockTerminal = jest.fn(({ sessionId, className }) => (
  <div 
    data-testid="mock-terminal"
    data-session-id={sessionId}
    className={className}
  >
    Mock Terminal - Session: {sessionId}
  </div>
));

// Mock Sidebar component
export const MockSidebar = jest.fn(({ 
  isOpen, 
  onToggle, 
  sessions, 
  activeSessionId,
  onSessionSelect,
  onSessionCreate,
  onSessionClose 
}) => (
  <div 
    data-testid="mock-sidebar"
    data-is-open={isOpen}
    data-active-session={activeSessionId}
  >
    <button onClick={onToggle}>Toggle</button>
    <button onClick={onSessionCreate}>New Session</button>
    {sessions.map(session => (
      <div key={session.id} data-testid={`session-${session.id}`}>
        <button onClick={() => onSessionSelect(session.id)}>
          {session.name}
        </button>
        <button onClick={() => onSessionClose(session.id)}>
          Close
        </button>
      </div>
    ))}
  </div>
));

// Mock MonitoringSidebar
export const MockMonitoringSidebar = jest.fn(() => (
  <div data-testid="mock-monitoring-sidebar">
    Mock Monitoring Sidebar
  </div>
));
```

### Hook Mocking

```typescript
// tests/mocks/HookMocks.ts
import { WebSocketHook } from '@/hooks/useWebSocket';

export const createMockWebSocketHook = (overrides?: Partial<WebSocketHook>) => ({
  connected: false,
  connecting: false,
  isConnected: false,
  connect: jest.fn(),
  disconnect: jest.fn(),
  sendMessage: jest.fn(),
  sendData: jest.fn(),
  resizeTerminal: jest.fn(),
  createSession: jest.fn(),
  destroySession: jest.fn(),
  listSessions: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  ...overrides,
});

export const createMockTerminalHook = (overrides?: any) => ({
  terminalRef: { current: null },
  terminal: null,
  backendTerminalConfig: { cols: 80, rows: 24 },
  focusTerminal: jest.fn(),
  fitTerminal: jest.fn(),
  ...overrides,
});
```

---

## 🌐 Network Mocking

### Fetch API Mocking

```typescript
// tests/mocks/NetworkMocks.ts
interface MockResponse {
  status: number;
  data: any;
  delay?: number;
}

export const createFetchMock = (responses: Record<string, MockResponse>) => {
  return jest.fn((url: string, options?) => {
    const mockResponse = responses[url] || {
      status: 404,
      data: { error: 'Not found' }
    };

    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          ok: mockResponse.status < 400,
          status: mockResponse.status,
          json: () => Promise.resolve(mockResponse.data),
          text: () => Promise.resolve(JSON.stringify(mockResponse.data)),
        });
      }, mockResponse.delay || 0);
    });
  });
};

// Usage example
const mockFetch = createFetchMock({
  '/api/sessions': {
    status: 200,
    data: { sessions: [] }
  },
  '/api/sessions/create': {
    status: 201,
    data: { sessionId: 'new-session' },
    delay: 100
  }
});

global.fetch = mockFetch;
```

---

## ⏰ Timer Mocking

### Jest Timer Utilities

```typescript
// tests/utils/timer-utils.ts
export const setupTimerMocks = () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });
};

export const advanceTimersByTime = (ms: number) => {
  act(() => {
    jest.advanceTimersByTime(ms);
  });
};

export const runAllTimers = () => {
  act(() => {
    jest.runAllTimers();
  });
};
```

---

## 🎬 Scenario-Based Mock Factories

### Common Test Scenarios

```typescript
// tests/factories/scenario-factories.ts
export const createConnectionScenario = (type: 'success' | 'failure' | 'slow' | 'timeout') => {
  switch (type) {
    case 'success':
      return createWebSocketMock();
    
    case 'failure':
      return createWebSocketMock({ shouldFail: true });
    
    case 'slow':
      return createWebSocketMock({ delayMs: 2000 });
    
    case 'timeout':
      return createWebSocketMock({ delayMs: 10000 });
  }
};

export const createSessionScenario = (sessionCount: number) => {
  return createStoreWithSessions(sessionCount);
};

export const createErrorScenario = (errorType: 'network' | 'websocket' | 'terminal') => {
  // Return appropriate mock configuration for error testing
  switch (errorType) {
    case 'network':
      return createFetchMock({
        '/api/*': { status: 500, data: { error: 'Server error' } }
      });
    
    case 'websocket':
      const wsClient = createWebSocketMock();
      setTimeout(() => wsClient.simulateConnectionError(), 100);
      return wsClient;
    
    case 'terminal':
      const backend = new MockTerminalBackend();
      // Setup to fail session creation
      backend.createSession = jest.fn().mockRejectedValue(new Error('PTY spawn failed'));
      return backend;
  }
};
```

---

## 🔧 Mock Configuration & Setup

### Jest Setup Integration

```typescript
// tests/setup-enhanced.ts
import { MockWebSocketClient } from './mocks/MockWebSocketClient';
import { MockTerminalBackend } from './mocks/MockTerminalBackend';

// Global mock setup
jest.mock('@/lib/websocket/client', () => ({
  wsClient: new MockWebSocketClient()
}));

jest.mock('node-pty', () => ({
  spawn: jest.fn().mockReturnValue({
    pid: 12345,
    write: jest.fn(),
    kill: jest.fn(),
    resize: jest.fn(),
    on: jest.fn(),
    removeAllListeners: jest.fn(),
  })
}));

// Custom matchers
expect.extend({
  toHaveBeenCalledWithEvent(received, event, data) {
    const calls = received.mock.calls;
    const matchingCall = calls.find(call => 
      call[0] === event && 
      (data ? JSON.stringify(call[1]) === JSON.stringify(data) : true)
    );
    
    return {
      pass: !!matchingCall,
      message: () => `Expected function to have been called with event "${event}"${data ? ` and data ${JSON.stringify(data)}` : ''}`
    };
  }
});
```

---

*This mock strategy documentation provides the foundation for creating isolated, reliable, and comprehensive tests that can simulate real-world scenarios without external dependencies.*