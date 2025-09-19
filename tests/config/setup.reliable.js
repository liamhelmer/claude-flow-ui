/**
 * Reliable Test Setup Configuration
 * Enhanced setup for stable and consistent test execution
 */

import '@testing-library/jest-dom';
import 'jest-axe/extend-expect';

// ============================================================================
// GLOBAL POLYFILLS AND MOCKS
// ============================================================================

// Performance API polyfill for older environments
if (typeof performance === 'undefined') {
  global.performance = {
    now: () => Date.now(),
    mark: () => {},
    measure: () => {},
    getEntriesByName: () => [],
    getEntriesByType: () => [],
  };
}

// ResizeObserver polyfill
global.ResizeObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// IntersectionObserver polyfill
global.IntersectionObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
  root: null,
  rootMargin: '',
  thresholds: [],
}));

// MutationObserver polyfill
global.MutationObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  disconnect: jest.fn(),
  takeRecords: jest.fn(),
}));

// WebSocket mock for testing
class MockWebSocket {
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.readyState = MockWebSocket.CONNECTING;
    this.bufferedAmount = 0;
    this.extensions = '';
    this.protocol = '';
    this.binaryType = 'blob';

    // Event handlers
    this.onopen = null;
    this.onclose = null;
    this.onmessage = null;
    this.onerror = null;

    // Simulate connection establishment
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen({ type: 'open', target: this });
      }
    }, 0);
  }

  send(data) {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
    // Mock sending behavior
  }

  close(code = 1000, reason = '') {
    this.readyState = MockWebSocket.CLOSING;
    setTimeout(() => {
      this.readyState = MockWebSocket.CLOSED;
      if (this.onclose) {
        this.onclose({ type: 'close', code, reason, target: this });
      }
    }, 0);
  }

  addEventListener(type, listener) {
    this[`on${type}`] = listener;
  }

  removeEventListener(type, listener) {
    if (this[`on${type}`] === listener) {
      this[`on${type}`] = null;
    }
  }

  dispatchEvent(event) {
    const handler = this[`on${event.type}`];
    if (handler) {
      handler(event);
    }
  }
}

MockWebSocket.CONNECTING = 0;
MockWebSocket.OPEN = 1;
MockWebSocket.CLOSING = 2;
MockWebSocket.CLOSED = 3;

global.WebSocket = MockWebSocket;

// ============================================================================
// DOM ENHANCEMENTS
// ============================================================================

// Enhanced HTMLElement with additional properties
Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
  value: jest.fn(),
  writable: true,
});

Object.defineProperty(HTMLElement.prototype, 'scroll', {
  value: jest.fn(),
  writable: true,
});

Object.defineProperty(HTMLElement.prototype, 'scrollTo', {
  value: jest.fn(),
  writable: true,
});

// Canvas context mock for terminal rendering
HTMLCanvasElement.prototype.getContext = jest.fn(() => ({
  clearRect: jest.fn(),
  fillRect: jest.fn(),
  fillText: jest.fn(),
  measureText: jest.fn(() => ({ width: 10 })),
  save: jest.fn(),
  restore: jest.fn(),
  scale: jest.fn(),
  translate: jest.fn(),
  rotate: jest.fn(),
  createImageData: jest.fn(),
  getImageData: jest.fn(),
  putImageData: jest.fn(),
  drawImage: jest.fn(),
  beginPath: jest.fn(),
  moveTo: jest.fn(),
  lineTo: jest.fn(),
  stroke: jest.fn(),
  fill: jest.fn(),
  arc: jest.fn(),
  rect: jest.fn(),
  closePath: jest.fn(),
}));

// ============================================================================
// CONSOLE CONFIGURATION
// ============================================================================

// Suppress specific console warnings in tests
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

console.error = (...args) => {
  // Suppress React 18 warnings about ReactDOM.render
  if (
    typeof args[0] === 'string' &&
    (args[0].includes('ReactDOM.render is no longer supported') ||
     args[0].includes('Warning: validateDOMNesting') ||
     args[0].includes('Warning: React.createFactory is deprecated'))
  ) {
    return;
  }
  originalConsoleError.apply(console, args);
};

console.warn = (...args) => {
  // Suppress specific warnings during tests
  if (
    typeof args[0] === 'string' &&
    (args[0].includes('componentWillReceiveProps has been renamed') ||
     args[0].includes('componentWillMount has been renamed') ||
     args[0].includes('findDOMNode is deprecated'))
  ) {
    return;
  }
  originalConsoleWarn.apply(console, args);
};

// ============================================================================
// TEST UTILITIES
// ============================================================================

// Global test utilities
global.testUtils = {
  // Async wait helper
  waitFor: (condition, timeout = 5000) => {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      const check = () => {
        if (condition()) {
          resolve();
        } else if (Date.now() - startTime >= timeout) {
          reject(new Error(`Condition not met within ${timeout}ms`));
        } else {
          setTimeout(check, 50);
        }
      };
      check();
    });
  },

  // Delay helper
  delay: (ms) => new Promise(resolve => setTimeout(resolve, ms)),

  // Mock data generators
  generateId: () => Math.random().toString(36).substring(2, 15),
  generateSessionData: (overrides = {}) => ({
    id: global.testUtils.generateId(),
    title: 'Test Session',
    isActive: true,
    createdAt: new Date(),
    ...overrides,
  }),
};

// ============================================================================
// ERROR HANDLING
// ============================================================================

// Global error handler for unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit the process in tests
});

// Global error handler for uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Don't exit the process in tests
});

// ============================================================================
// CLEANUP
// ============================================================================

// Global cleanup after each test
afterEach(() => {
  // Clear all timers
  jest.clearAllTimers();

  // Clear all mocks
  jest.clearAllMocks();

  // Restore console methods if needed
  if (process.env.RESTORE_CONSOLE === 'true') {
    console.error = originalConsoleError;
    console.warn = originalConsoleWarn;
  }

  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
});

// Global setup before all tests
beforeAll(() => {
  // Set test-specific environment variables
  process.env.NODE_ENV = 'test';
  process.env.TEST_ENV = 'jest';

  // Increase timeout for slow operations
  jest.setTimeout(30000);
});

// Global cleanup after all tests
afterAll(() => {
  // Final cleanup
  jest.restoreAllMocks();
  jest.clearAllTimers();

  // Restore original console methods
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
});

// ============================================================================
// TEST ENVIRONMENT VALIDATION
// ============================================================================

// Validate test environment setup
if (typeof window !== 'undefined') {
  // Ensure required DOM APIs are available
  const requiredAPIs = [
    'document',
    'localStorage',
    'sessionStorage',
    'WebSocket',
    'ResizeObserver',
    'IntersectionObserver',
    'MutationObserver',
  ];

  const missingAPIs = requiredAPIs.filter(api => !(api in window));
  if (missingAPIs.length > 0) {
    console.warn('Missing APIs in test environment:', missingAPIs);
  }
}

console.log('✅ Reliable test setup completed successfully');

export {};