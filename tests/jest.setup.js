// Jest DOM matchers are imported in setup.ts to avoid conflicts

// Mock WebSocket for tests
global.WebSocket = class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = WebSocket.CONNECTING;
    setTimeout(() => {
      this.readyState = WebSocket.OPEN;
      this.onopen?.();
    }, 0);
  }
  
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  
  send(data) {
    // Mock implementation
  }
  
  close() {
    this.readyState = WebSocket.CLOSED;
    this.onclose?.();
  }
};

// Mock node-pty for terminal tests
jest.mock('node-pty', () => ({
  spawn: jest.fn(() => ({
    onData: jest.fn(),
    onExit: jest.fn(),
    write: jest.fn(),
    resize: jest.fn(),
    kill: jest.fn(),
    pid: 1234,
  })),
}));

// Mock socket.io for tests
jest.mock('socket.io-client', () => ({
  io: jest.fn(() => ({
    connected: true,
    connect: jest.fn(),
    disconnect: jest.fn(),
    emit: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    id: 'mock-socket-id',
  })),
}));

// Mock xterm for terminal tests
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(() => ({
    open: jest.fn(),
    dispose: jest.fn(),
    write: jest.fn(),
    writeln: jest.fn(),
    clear: jest.fn(),
    focus: jest.fn(),
    blur: jest.fn(),
    resize: jest.fn(),
    onData: jest.fn(),
    onResize: jest.fn(),
    onKey: jest.fn(),
    cols: 80,
    rows: 24,
    element: document.createElement('div'),
  })),
}));

jest.mock('@xterm/addon-fit', () => ({
  FitAddon: jest.fn(() => ({
    fit: jest.fn(),
    proposeDimensions: jest.fn(() => ({ cols: 80, rows: 24 })),
    activate: jest.fn(),
    dispose: jest.fn(),
  })),
}));

// Mock Next.js router
jest.mock('next/router', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
    back: jest.fn(),
    reload: jest.fn(),
    pathname: '/',
    query: {},
    asPath: '/',
  }),
}));

// Mock environment variables
process.env.NEXT_PUBLIC_WS_PORT = '11236';
process.env.NEXT_PUBLIC_WS_URL = 'ws://localhost:11236';

// Console warning suppression for tests
const originalWarn = console.warn;
beforeAll(() => {
  console.warn = (...args) => {
    const message = args[0];
    if (
      typeof message === 'string' &&
      (message.includes('ReactDOM.render') ||
       message.includes('Warning: ') ||
       message.includes('validateDOMNesting'))
    ) {
      return;
    }
    originalWarn.call(console, ...args);
  };
});

afterAll(() => {
  console.warn = originalWarn;
});

// Global test utilities
global.testUtils = {
  createMockTerminalSession: (overrides = {}) => ({
    id: 'test-session-1',
    name: 'Test Terminal',
    isActive: true,
    lastActivity: new Date(),
    ...overrides,
  }),
  
  createMockWebSocketMessage: (overrides = {}) => ({
    type: 'data',
    sessionId: 'test-session-1',
    data: 'test data',
    ...overrides,
  }),
  
  mockSystemMetrics: {
    memoryTotal: 17179869184,
    memoryUsed: 15000000000,
    memoryFree: 2179869184,
    memoryUsagePercent: 87.3,
    memoryEfficiency: 15.2,
    cpuCount: 10,
    cpuLoad: 1.2,
    platform: 'darwin',
    uptime: 1234567,
    timestamp: Date.now(),
  },
  
  mockAgentStatus: {
    agentId: 'agent-1',
    state: 'idle',
    currentTask: undefined,
  },
  
  wait: (ms = 0) => new Promise(resolve => setTimeout(resolve, ms)),
};