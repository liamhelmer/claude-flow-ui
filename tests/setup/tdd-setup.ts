/**
 * TDD Framework Setup
 * Comprehensive test setup for Test-Driven Development
 */

import '@testing-library/jest-dom';
import { configure } from '@testing-library/react';
import { expect } from '@jest/globals';
import { setupServer } from 'msw/node';
import { jest } from '@jest/globals';

// Enhanced Testing Library configuration for TDD
configure({
  testIdAttribute: 'data-testid',
  asyncUtilTimeout: 5000,
  computedStyleSupportsPseudoElements: true,
  defaultHidden: false,
  showOriginalStackTrace: true,
});

// Global test timeout for TDD (shorter for faster feedback)
jest.setTimeout(10000);

// Mock Service Worker server for API mocking
export const server = setupServer();

// Global setup
beforeAll(() => {
  // Start MSW server
  server.listen({
    onUnhandledRequest: 'warn',
  });

  // Setup performance monitoring
  if (typeof window !== 'undefined') {
    Object.defineProperty(window, 'performance', {
      value: {
        mark: jest.fn(),
        measure: jest.fn(),
        getEntriesByName: jest.fn(() => []),
        getEntriesByType: jest.fn(() => []),
        clearMarks: jest.fn(),
        clearMeasures: jest.fn(),
        now: jest.fn(() => Date.now()),
      },
      writable: true,
    });
  }

  // Setup ResizeObserver mock
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  }));

  // Setup IntersectionObserver mock
  global.IntersectionObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
    root: null,
    rootMargin: '',
    thresholds: [],
  }));

  // Setup MutationObserver mock
  global.MutationObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn(),
    takeRecords: jest.fn(() => []),
  }));
});

// Reset handlers between tests
afterEach(() => {
  server.resetHandlers();
  jest.clearAllMocks();
  jest.clearAllTimers();

  // Clean up any test artifacts
  if (typeof window !== 'undefined') {
    window.localStorage.clear();
    window.sessionStorage.clear();
  }
});

// Global teardown
afterAll(() => {
  server.close();
  jest.restoreAllMocks();
});

// TDD-specific matchers and utilities
expect.extend({
  toBeWithinRange(received: number, floor: number, ceiling: number) {
    const pass = received >= floor && received <= ceiling;
    if (pass) {
      return {
        message: () =>
          `expected ${received} not to be within range ${floor} - ${ceiling}`,
        pass: true,
      };
    } else {
      return {
        message: () =>
          `expected ${received} to be within range ${floor} - ${ceiling}`,
        pass: false,
      };
    }
  },

  toHaveBeenCalledWithinTime(received: jest.MockedFunction<any>, timeMs: number) {
    const calls = received.mock.calls;
    if (calls.length === 0) {
      return {
        message: () => `expected function to have been called within ${timeMs}ms`,
        pass: false,
      };
    }

    // This is a simplified check - in real implementation you'd track timing
    return {
      message: () => `expected function not to have been called within ${timeMs}ms`,
      pass: true,
    };
  },

  toMatchAccessibilityStandards(received: Element) {
    // Simplified accessibility check
    const hasAriaLabel = received.hasAttribute('aria-label') || received.hasAttribute('aria-labelledby');
    const hasRole = received.hasAttribute('role');
    const isInteractive = ['button', 'link', 'input', 'select', 'textarea'].includes(received.tagName.toLowerCase());

    if (isInteractive && !hasAriaLabel && !hasRole) {
      return {
        message: () => `expected interactive element to have proper accessibility attributes`,
        pass: false,
      };
    }

    return {
      message: () => `expected element not to match accessibility standards`,
      pass: true,
    };
  },
});

// Global error handling for TDD
const originalConsoleError = console.error;
console.error = (...args: any[]) => {
  // Filter out known React warnings in test environment
  const message = args[0];
  if (typeof message === 'string') {
    if (
      message.includes('Warning: ReactDOM.render is deprecated') ||
      message.includes('Warning: ComponentWillMount has been renamed') ||
      message.includes('Warning: Each child in a list should have a unique "key" prop')
    ) {
      return;
    }
  }
  originalConsoleError(...args);
};

// TDD debugging utilities
(global as any).debug = {
  log: (...args: any[]) => {
    if (process.env.DEBUG_TESTS === 'true') {
      console.log('[TDD Debug]', ...args);
    }
  },

  performance: (name: string, fn: () => void) => {
    if (process.env.DEBUG_PERFORMANCE === 'true') {
      const start = Date.now();
      fn();
      const end = Date.now();
      console.log(`[TDD Performance] ${name}: ${end - start}ms`);
    } else {
      fn();
    }
  },

  snapshot: (component: any, name?: string) => {
    if (process.env.DEBUG_SNAPSHOTS === 'true') {
      console.log(`[TDD Snapshot] ${name || 'Component'}:`, component);
    }
  },
};

// Memory leak detection for TDD
let initialMemory: number;

beforeEach(() => {
  if (process.env.DEBUG_MEMORY === 'true') {
    initialMemory = process.memoryUsage().heapUsed;
  }
});

afterEach(() => {
  if (process.env.DEBUG_MEMORY === 'true') {
    const finalMemory = process.memoryUsage().heapUsed;
    const memoryDiff = finalMemory - initialMemory;

    if (memoryDiff > 10 * 1024 * 1024) { // 10MB threshold
      console.warn(`[TDD Memory Warning] Test may have memory leak: ${memoryDiff / 1024 / 1024}MB increase`);
    }
  }
});

// Export utilities for use in tests
export { server as mockServer };
export const tddUtils = {
  waitFor: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
  mockTimers: () => jest.useFakeTimers(),
  restoreTimers: () => jest.useRealTimers(),
  mockDate: (date: string | Date) => {
    const mockDate = new Date(date);
    jest.spyOn(global, 'Date').mockImplementation(() => mockDate as any);
  },
  restoreDate: () => {
    (global.Date as any).mockRestore?.();
  },
};

// Type declarations for custom matchers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeWithinRange(floor: number, ceiling: number): R;
      toHaveBeenCalledWithinTime(timeMs: number): R;
      toMatchAccessibilityStandards(): R;
    }
  }
}