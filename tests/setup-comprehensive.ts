/**
 * Enhanced test setup for Claude Flow UI
 * Provides comprehensive mocking and utilities for unit testing
 */

import '@testing-library/jest-dom';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, beforeAll, afterAll } from '@jest/globals';

// Import mocks
import './mocks';
import './mocks/xterm';
import './mocks/websocket';

// Enhanced console suppression with selective logging
const originalConsole = global.console;
const mockConsole = {
  ...originalConsole,
  debug: jest.fn(),
  log: process.env.VERBOSE_TESTS === 'true' ? originalConsole.log : jest.fn(),
  info: process.env.VERBOSE_TESTS === 'true' ? originalConsole.info : jest.fn(),
  warn: originalConsole.warn, // Keep warnings visible
  error: originalConsole.error, // Keep errors visible
};

// Setup and teardown hooks
beforeAll(() => {
  // Suppress console output during tests unless explicitly enabled
  if (process.env.VERBOSE_TESTS !== 'true') {
    global.console = mockConsole;
  }

  // Set up global test environment
  process.env.NODE_ENV = 'test';

  // Mock next/router for Next.js components
  jest.mock('next/router', () => ({
    useRouter: () => ({
      route: '/',
      pathname: '/',
      query: {},
      asPath: '/',
      push: jest.fn(),
      pop: jest.fn(),
      reload: jest.fn(),
      back: jest.fn(),
      prefetch: jest.fn().mockResolvedValue(undefined),
      beforePopState: jest.fn(),
      events: {
        on: jest.fn(),
        off: jest.fn(),
        emit: jest.fn(),
      },
      isFallback: false,
      isReady: true,
      isPreview: false,
    }),
    withRouter: (Component: any) => Component,
  }));

  // Mock next/image
  jest.mock('next/image', () => ({
    __esModule: true,
    default: ({ src, alt, ...props }: any) => <img src={src} alt={alt} {...props} />,
  }));

  // Mock environment variables
  process.env.NEXT_PUBLIC_WS_URL = 'ws://localhost:3001';
  process.env.NEXT_PUBLIC_API_URL = 'http://localhost:3001';
});

afterAll(() => {
  // Restore original console
  if (process.env.VERBOSE_TESTS !== 'true') {
    global.console = originalConsole;
  }
});

beforeEach(() => {
  // Clear all mocks before each test
  jest.clearAllMocks();

  // Reset DOM
  document.body.innerHTML = '';
  document.head.innerHTML = '';

  // Reset window properties
  Object.defineProperty(window, 'innerWidth', {
    writable: true,
    configurable: true,
    value: 1024,
  });

  Object.defineProperty(window, 'innerHeight', {
    writable: true,
    configurable: true,
    value: 768,
  });

  // Reset location
  Object.defineProperty(window, 'location', {
    writable: true,
    configurable: true,
    value: {
      href: 'http://localhost:3000',
      origin: 'http://localhost:3000',
      protocol: 'http:',
      host: 'localhost:3000',
      hostname: 'localhost',
      port: '3000',
      pathname: '/',
      search: '',
      hash: '',
      reload: jest.fn(),
      replace: jest.fn(),
      assign: jest.fn(),
    },
  });

  // Reset timers
  jest.useFakeTimers();

  // Set up default viewport
  global.innerWidth = 1024;
  global.innerHeight = 768;
});

afterEach(() => {
  // Cleanup React Testing Library
  cleanup();

  // Run all pending timers
  jest.runOnlyPendingTimers();
  jest.useRealTimers();

  // Clear all intervals and timeouts
  jest.clearAllTimers();

  // Reset WebSocket mocks
  if (global.MockWebSocket) {
    global.MockWebSocket.reset();
  }

  // Clean up any remaining event listeners
  document.removeEventListener = jest.fn();
  window.removeEventListener = jest.fn();
});

// Custom matchers
expect.extend({
  toHaveBeenCalledWithSessionId: (received, sessionId) => {
    const calls = received.mock.calls;
    const matchingCall = calls.find(call =>
      call.some(arg =>
        typeof arg === 'string' && arg.includes(sessionId) ||
        typeof arg === 'object' && arg?.sessionId === sessionId
      )
    );

    return {
      message: () =>
        matchingCall
          ? `Expected not to be called with sessionId "${sessionId}"`
          : `Expected to be called with sessionId "${sessionId}"`,
      pass: !!matchingCall,
    };
  },

  toHaveValidTerminalDimensions: (received) => {
    const isValid = received?.cols > 0 && received?.rows > 0;
    return {
      message: () =>
        isValid
          ? `Expected terminal to not have valid dimensions`
          : `Expected terminal to have valid dimensions (cols > 0, rows > 0), got cols: ${received?.cols}, rows: ${received?.rows}`,
      pass: isValid,
    };
  },

  toBeConnectedWebSocket: (received) => {
    const isConnected = received?.connected === true || received?.readyState === 1;
    return {
      message: () =>
        isConnected
          ? `Expected WebSocket to not be connected`
          : `Expected WebSocket to be connected`,
      pass: isConnected,
    };
  },
});

// Global test utilities
global.testUtils = {
  // Simulate user interaction delays
  waitForUser: (ms = 100) => new Promise(resolve => setTimeout(resolve, ms)),

  // Fast forward timers and flush promises
  flushPromises: async () => {
    jest.runAllTimers();
    await new Promise(resolve => setImmediate(resolve));
  },

  // Create a mock terminal session
  createMockSession: (overrides = {}) => ({
    id: `session-${Date.now()}`,
    name: 'Test Terminal',
    isActive: true,
    lastActivity: new Date(),
    ...overrides,
  }),

  // Create mock WebSocket message
  createMockMessage: (type, data) => ({
    type,
    data,
    timestamp: Date.now(),
    sessionId: 'test-session',
  }),

  // Wait for React state updates
  waitForStateUpdate: () => new Promise(resolve => {
    jest.runAllTimers();
    setImmediate(resolve);
  }),

  // Simulate terminal input
  simulateTerminalInput: (terminal, input) => {
    if (terminal?.onData) {
      terminal.onData(input);
    }
  },

  // Simulate resize event
  simulateResize: (width = 1024, height = 768) => {
    global.innerWidth = width;
    global.innerHeight = height;
    window.dispatchEvent(new Event('resize'));
  },

  // Clean up test environment
  cleanup: () => {
    jest.clearAllMocks();
    jest.clearAllTimers();
    cleanup();
  },
};

// Error boundary for tests
class TestErrorBoundary extends Error {
  constructor(message: string, componentStack?: string) {
    super(message);
    this.name = 'TestErrorBoundary';
    this.componentStack = componentStack;
  }
  componentStack?: string;
}

global.TestErrorBoundary = TestErrorBoundary;

// Silence act warnings in tests
const originalError = console.error;
console.error = (...args) => {
  if (
    typeof args[0] === 'string' &&
    args[0].includes('Warning: An invalid form control')
  ) {
    return;
  }
  if (
    typeof args[0] === 'string' &&
    args[0].includes('Warning: validateDOMNesting')
  ) {
    return;
  }
  originalError.call(console, ...args);
};

// Export types for TypeScript
declare global {
  namespace jest {
    interface Matchers<R> {
      toHaveBeenCalledWithSessionId(sessionId: string): R;
      toHaveValidTerminalDimensions(): R;
      toBeConnectedWebSocket(): R;
    }
  }

  const testUtils: {
    waitForUser: (ms?: number) => Promise<void>;
    flushPromises: () => Promise<void>;
    createMockSession: (overrides?: any) => any;
    createMockMessage: (type: string, data: any) => any;
    waitForStateUpdate: () => Promise<void>;
    simulateTerminalInput: (terminal: any, input: string) => void;
    simulateResize: (width?: number, height?: number) => void;
    cleanup: () => void;
  };

  const TestErrorBoundary: typeof Error;
}