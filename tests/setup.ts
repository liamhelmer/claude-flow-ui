/**
 * Consolidated Jest Test Setup
 * Provides unified mocks and utilities for all tests
 */
import '@testing-library/jest-dom';
import React from 'react';

// Polyfill setImmediate for jsdom environment
if (typeof global.setImmediate === 'undefined') {
  (global as any).setImmediate = (callback: (...args: any[]) => void, ...args: any[]) => {
    return setTimeout(callback, 0, ...args);
  };
}

if (typeof global.clearImmediate === 'undefined') {
  (global as any).clearImmediate = (immediateId: NodeJS.Immediate) => {
    clearTimeout(immediateId as any);
  };
}

// Environment setup
process.env = {
  ...process.env,
  NODE_ENV: 'test',
  NEXT_PUBLIC_WS_URL: 'ws://localhost:11237',
  NEXT_PUBLIC_WS_PORT: '11237',
};

// === WEBSOCKET MOCKS ===
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
  private _destroyed = false;

  constructor(url: string) {
    this.url = url;
    // Use immediate scheduling for more predictable timing
    setImmediate(() => {
      if (!this._destroyed) {
        this.readyState = MockWebSocket.OPEN;
        if (this.onopen) {
          this.onopen(new Event('open'));
        }
      }
    });
  }

  send(data: string | Buffer) {
    // Silent mock - avoid console spam in tests
    if (this._destroyed) return;
  }

  close(code?: number, reason?: string) {
    if (this._destroyed) return;
    this._destroyed = true;
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code, reason }));
    }
  }

  addEventListener(type: string, listener: EventListener) {
    if (this._destroyed) return;
    if (type === 'open') this.onopen = listener;
    else if (type === 'close') this.onclose = listener as any;
    else if (type === 'error') this.onerror = listener;
    else if (type === 'message') this.onmessage = listener as any;
  }

  removeEventListener(type: string, listener: EventListener) {
    if (type === 'open') this.onopen = null;
    else if (type === 'close') this.onclose = null;
    else if (type === 'error') this.onerror = null;
    else if (type === 'message') this.onmessage = null;
  }
}

// @ts-ignore
global.WebSocket = MockWebSocket;

// === BROWSER API MOCKS ===

// ResizeObserver mock for xterm.js
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// IntersectionObserver mock
global.IntersectionObserver = class IntersectionObserver {
  root: Element | null = null;
  rootMargin: string = '0px';
  thresholds: ReadonlyArray<number> = [0];
  
  constructor(callback: IntersectionObserverCallback, options?: IntersectionObserverInit) {}
  observe(target: Element): void {}
  unobserve(target: Element): void {}
  disconnect(): void {}
  takeRecords(): IntersectionObserverEntry[] { return []; }
} as any;

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
  beginPath: jest.fn(),
  moveTo: jest.fn(),
  lineTo: jest.fn(),
  closePath: jest.fn(),
  stroke: jest.fn(),
  fill: jest.fn(),
  arc: jest.fn(),
  rect: jest.fn(),
  clip: jest.fn(),
  translate: jest.fn(),
  scale: jest.fn(),
  rotate: jest.fn(),
  transform: jest.fn(),
};

// HTMLCanvasElement mock
if (typeof HTMLCanvasElement !== 'undefined') {
  HTMLCanvasElement.prototype.getContext = jest.fn(() => mockCanvasContext) as any;
}

// matchMedia mock for responsive design
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

// === MODULE MOCKS ===

// Mock Next.js router
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

// Mock Next.js dynamic imports
jest.mock('next/dynamic', () => {
  const mockDynamic = (fn: () => any, options?: any) => {
    const Component = (props: any) => {
      if (options?.loading) {
        return React.createElement(options.loading);
      }
      
      try {
        const DynamicComponent = fn();
        
        // Handle Promise-based dynamic imports
        if (typeof DynamicComponent?.then === 'function') {
          return React.createElement('div', { 'data-testid': 'loading-dynamic' }, 'Loading...');
        }
        
        // Handle ES modules with default export
        const ComponentToRender = DynamicComponent?.default || DynamicComponent;
        
        // Ensure we have a valid component
        if (typeof ComponentToRender === 'function') {
          return React.createElement(ComponentToRender, props);
        }
        
        // Fallback for invalid components
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

// Mock xterm.js
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

// Mock Socket.IO client with proper cleanup
jest.mock('socket.io-client', () => {
  let mockSocket: any;
  
  const createMockSocket = () => {
    if (mockSocket) {
      // Clean up previous socket
      mockSocket.connected = false;
      mockSocket.disconnected = true;
    }
    
    mockSocket = {
      id: 'mock-socket-id-' + Date.now(),
      connected: false,
      disconnected: true,
      on: jest.fn(),
      off: jest.fn(),
      emit: jest.fn(),
      connect: jest.fn(() => {
        mockSocket.connected = true;
        mockSocket.disconnected = false;
        return mockSocket;
      }),
      disconnect: jest.fn(() => {
        mockSocket.connected = false;
        mockSocket.disconnected = true;
        return mockSocket;
      }),
      removeAllListeners: jest.fn(),
      close: jest.fn(),
    };
    
    return mockSocket;
  };
  
  return {
    io: jest.fn(() => createMockSocket()),
    Socket: jest.fn(() => createMockSocket()),
  };
});

// Mock node-pty (server-side only)
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

// === CONSOLE SUPPRESSION ===
const originalWarn = console.warn;
const originalError = console.error;
const originalLog = console.log;

// Enhanced error tracking for debugging
let testErrors: Array<{ test: string; error: any; timestamp: number }> = [];

// Enhanced test isolation per test
beforeEach(() => {
  // Clear all timers before each test
  jest.clearAllTimers();
  
  // Reset all mocks
  jest.clearAllMocks();
});

afterEach(async () => {
  // Clean up any pending timers (only if fake timers are enabled)
  try {
    if (jest.isMockFunction(setTimeout)) {
      jest.runOnlyPendingTimers();
    }
  } catch (error) {
    // Ignore timer cleanup errors
  }
  
  // Flush any pending promises
  if (global.testUtils && global.testUtils.flushPromises) {
    await global.testUtils.flushPromises();
  }
  
  // Force cleanup of any hanging resources
  if (global.gc) {
    global.gc();
  }
});

beforeAll(() => {
  // Prevent EventEmitter memory leaks in tests
  process.setMaxListeners(0);
  
  // Use fake timers for more predictable tests
  jest.useFakeTimers({
    advanceTimers: true,
    doNotFake: ['nextTick', 'setImmediate', 'clearImmediate', 'Date'],
    legacyFakeTimers: false
  });
  
  // Suppress known harmless warnings in tests
  console.warn = (...args) => {
    const message = args[0];
    if (
      typeof message === 'string' &&
      (
        message.includes('ReactDOM.render is no longer supported') ||
        message.includes('Warning: componentWillReceiveProps') ||
        message.includes('Warning: componentWillUpdate') ||
        message.includes('Warning: componentWillMount') ||
        message.includes('validateDOMNesting') ||
        message.includes('React.createElement: type is invalid') ||
        message.includes('MaxListenersExceededWarning')
      )
    ) {
      return;
    }
    originalWarn.call(console, ...args);
  };
  
  console.error = (...args) => {
    const message = args[0];
    if (
      typeof message === 'string' &&
      (
        message.includes('Warning: ') ||
        message.includes('The above error occurred')
      )
    ) {
      return;
    }
    originalError.call(console, ...args);
  };
});

afterAll(() => {
  // Restore real timers
  jest.useRealTimers();
  
  // Restore original console methods
  console.warn = originalWarn;
  console.error = originalError;
  console.log = originalLog;
  
  // Report test errors if in debug mode
  if (process.env.DEBUG_TESTS === 'true' && testErrors.length > 0) {
    originalLog('\n=== TEST ERRORS SUMMARY ===');
    testErrors.forEach(({ test, error, timestamp }) => {
      originalLog(`[${new Date(timestamp).toISOString()}] ${test}: ${error}`);
    });
    originalLog('=== END TEST ERRORS ===\n');
  }
  
  // Clear error tracking
  testErrors = [];
  
  // Final cleanup
  if (global.gc) {
    global.gc();
  }
});

// === GLOBAL TEST UTILITIES ===
declare global {
  var testUtils: {
    createMockTerminalSession: (overrides?: any) => any;
    createMockWebSocketMessage: (overrides?: any) => any;
    mockSystemMetrics: any;
    mockAgentStatus: any;
    wait: (ms?: number) => Promise<void>;
    mockLocalStorage: () => void;
    mockSessionStorage: () => void;
    flushPromises: () => Promise<void>;
    waitForNextTick: () => Promise<void>;
    debugTest: (message: string, data?: any) => void;
    isolateTest: (testFn: () => void | Promise<void>) => () => Promise<void>;
  };
}

global.testUtils = {
  createMockTerminalSession: (overrides = {}) => ({
    id: 'test-session-1',
    name: 'Test Terminal',
    isActive: true,
    lastActivity: new Date().toISOString(),
    ...overrides,
  }),
  
  createMockWebSocketMessage: (overrides = {}) => ({
    type: 'data',
    sessionId: 'test-session-1',
    data: 'test data',
    timestamp: Date.now(),
    ...overrides,
  }),
  
  mockSystemMetrics: {
    memoryTotal: 17179869184,
    memoryUsed: 15000000000,
    memoryFree: 2179869184,
    memoryUsagePercent: 87.3,
    memoryEfficiency: 15.2,
    cpuCount: 10,
    cpuLoad: [1.2, 1.1, 1.0],
    platform: 'darwin',
    uptime: 1234567,
    timestamp: Date.now(),
  },
  
  mockAgentStatus: {
    agentId: 'agent-1',
    state: 'idle',
    currentTask: undefined,
    lastActivity: Date.now(),
  },
  
  wait: (ms = 0) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // CRITICAL: flushPromises utility for test reliability
  flushPromises: () => new Promise(resolve => setImmediate(resolve)),
  
  waitForNextTick: () => new Promise(resolve => process.nextTick(resolve)),
  
  debugTest: (message: string, data?: any) => {
    if (process.env.DEBUG_TESTS === 'true') {
      originalLog(`[TEST DEBUG] ${message}`, data ? JSON.stringify(data, null, 2) : '');
    }
  },
  
  isolateTest: (testFn: () => void | Promise<void>) => {
    return async () => {
      // Clear all mocks before test
      jest.clearAllMocks();
      
      try {
        await testFn();
      } finally {
        // Cleanup after test
        if (global.testUtils.flushPromises) {
          await global.testUtils.flushPromises();
        }
        jest.clearAllMocks();
      }
    };
  },
  
  mockLocalStorage: () => {
    const store: { [key: string]: string } = {};
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: (key: string) => store[key] || null,
        setItem: (key: string, value: string) => { store[key] = value; },
        removeItem: (key: string) => { delete store[key]; },
        clear: () => { Object.keys(store).forEach(key => delete store[key]); },
        length: Object.keys(store).length,
        key: (index: number) => Object.keys(store)[index] || null,
      },
    });
  },
  
  mockSessionStorage: () => {
    const store: { [key: string]: string } = {};
    Object.defineProperty(window, 'sessionStorage', {
      value: {
        getItem: (key: string) => store[key] || null,
        setItem: (key: string, value: string) => { store[key] = value; },
        removeItem: (key: string) => { delete store[key]; },
        clear: () => { Object.keys(store).forEach(key => delete store[key]); },
        length: Object.keys(store).length,
        key: (index: number) => Object.keys(store)[index] || null,
      },
    });
  },
};

// Initialize localStorage and sessionStorage mocks
global.testUtils.mockLocalStorage();
global.testUtils.mockSessionStorage();