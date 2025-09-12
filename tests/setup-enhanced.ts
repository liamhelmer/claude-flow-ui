/**
 * Enhanced Test Setup - Claude UI Testing Framework
 * Comprehensive test environment configuration
 */

import '@testing-library/jest-dom';
// Import mocks conditionally to prevent circular dependencies
let setupPerformanceTesting: () => void;
let setupWebSocketTesting: () => void;

try {
  ({ setupPerformanceTesting } = require('./mocks/performance'));
  ({ setupWebSocketTesting } = require('./mocks/websocket-enhanced'));
} catch (error) {
  console.warn('Mock modules not available, using fallbacks');
  setupPerformanceTesting = () => {};
  setupWebSocketTesting = () => {};
}

// Global test configuration
interface TestConfig {
  timeout: number;
  retryAttempts: number;
  debugMode: boolean;
  silentConsole: boolean;
  memoryThreshold: number;
  performanceThreshold: number;
}

const testConfig: TestConfig = {
  timeout: parseInt(process.env.TEST_TIMEOUT || '5000', 10),
  retryAttempts: parseInt(process.env.TEST_RETRY_ATTEMPTS || '0', 10),
  debugMode: process.env.TEST_DEBUG === 'true',
  silentConsole: process.env.NODE_ENV === 'test' && process.env.TEST_VERBOSE !== 'true',
  memoryThreshold: 50 * 1024 * 1024, // 50MB
  performanceThreshold: 100, // 100ms
};

// Console management for cleaner test output
const originalConsole = { ...console };
const consoleBuffer: Array<{ type: string; args: any[]; timestamp: number }> = [];

const mockConsole = {
  log: jest.fn((...args) => {
    if (testConfig.debugMode) originalConsole.log(...args);
    consoleBuffer.push({ type: 'log', args, timestamp: Date.now() });
  }),
  warn: jest.fn((...args) => {
    if (testConfig.debugMode) originalConsole.warn(...args);
    consoleBuffer.push({ type: 'warn', args, timestamp: Date.now() });
  }),
  error: jest.fn((...args) => {
    originalConsole.error(...args); // Always show errors
    consoleBuffer.push({ type: 'error', args, timestamp: Date.now() });
  }),
  info: jest.fn((...args) => {
    if (testConfig.debugMode) originalConsole.info(...args);
    consoleBuffer.push({ type: 'info', args, timestamp: Date.now() });
  }),
  debug: jest.fn((...args) => {
    if (testConfig.debugMode) originalConsole.debug(...args);
    consoleBuffer.push({ type: 'debug', args, timestamp: Date.now() });
  }),
};

// Apply console mocking conditionally
if (testConfig.silentConsole) {
  Object.assign(console, mockConsole);
}

// Global DOM mocks
const setupDOMMocks = (): void => {
  // ResizeObserver mock
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  }));

  // IntersectionObserver mock
  global.IntersectionObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
    root: null,
    rootMargin: '',
    thresholds: [],
  }));

  // MutationObserver mock
  global.MutationObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn(),
    takeRecords: jest.fn(() => []),
  }));

  // matchMedia mock - only in browser environment
  if (typeof window !== 'undefined' && !window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      configurable: true,
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
  }

  // localStorage mock
  const localStorageMock = {
    getItem: jest.fn((key: string) => null),
    setItem: jest.fn((key: string, value: string) => {}),
    removeItem: jest.fn((key: string) => {}),
    clear: jest.fn(() => {}),
    length: 0,
    key: jest.fn((index: number) => null),
  };

  if (!Object.getOwnPropertyDescriptor(window, 'localStorage')) {
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
      configurable: true,
    });
  }

  // sessionStorage mock
  if (!Object.getOwnPropertyDescriptor(window, 'sessionStorage')) {
    Object.defineProperty(window, 'sessionStorage', {
      value: { ...localStorageMock },
      writable: true,
      configurable: true,
    });
  }

  // Location mock - check if already defined to avoid redefinition error
  if (!Object.getOwnPropertyDescriptor(window, 'location')) {
    Object.defineProperty(window, 'location', {
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
        assign: jest.fn(),
        replace: jest.fn(),
        reload: jest.fn(),
        toString: jest.fn(() => 'http://localhost:3000'),
      },
      writable: true,
      configurable: true,
    });
  }

  // Navigator mock - check if already defined to avoid redefinition error
  if (!Object.getOwnPropertyDescriptor(window, 'navigator')) {
    Object.defineProperty(window, 'navigator', {
      value: {
        userAgent: 'jest',
        language: 'en-US',
        languages: ['en-US', 'en'],
        platform: 'linux',
        clipboard: {
          writeText: jest.fn(() => Promise.resolve()),
          readText: jest.fn(() => Promise.resolve('')),
        },
      },
      writable: true,
      configurable: true,
    });
  }

  // URL mock
  global.URL.createObjectURL = jest.fn(() => 'mocked-url');
  global.URL.revokeObjectURL = jest.fn();

  // File and FileReader mocks
  global.File = jest.fn().mockImplementation((parts, name, properties) => ({
    name,
    size: parts.reduce((acc: number, part: any) => acc + (part.length || 0), 0),
    type: properties?.type || '',
    lastModified: Date.now(),
  })) as any;

  global.FileReader = jest.fn().mockImplementation(() => ({
    readAsText: jest.fn(),
    readAsDataURL: jest.fn(),
    readAsArrayBuffer: jest.fn(),
    result: null,
    error: null,
    onload: null,
    onerror: null,
    onprogress: null,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
  })) as any;
};

// Test utilities for memory and performance tracking
const setupTestUtilities = (): void => {
  (global as any).testUtils = {
    consoleBuffer,
    clearConsoleBuffer: () => {
      consoleBuffer.length = 0;
    },
    getConsoleOutput: (type?: string) => {
      return type
        ? consoleBuffer.filter(entry => entry.type === type)
        : consoleBuffer;
    },
    flushAsyncOperations: () => {
      return new Promise(resolve => {
        setTimeout(resolve, 0);
      });
    },
    waitForCondition: async (
      condition: () => boolean,
      timeout: number = 1000,
      interval: number = 10
    ): Promise<void> => {
      const startTime = Date.now();
      
      while (!condition()) {
        if (Date.now() - startTime > timeout) {
          throw new Error(`Condition not met within ${timeout}ms`);
        }
        await new Promise(resolve => setTimeout(resolve, interval));
      }
    },
  };
};

// Error boundary for test isolation
const setupErrorHandling = (): void => {
  // Global error handler
  const originalOnError = window.onerror;
  window.onerror = (message, source, lineno, colno, error) => {
    if (testConfig.debugMode) {
      originalConsole.error('Global error:', { message, source, lineno, colno, error });
    }
    return originalOnError ? originalOnError(message, source, lineno, colno, error) : false;
  };

  // Unhandled promise rejection handler
  const originalOnUnhandledRejection = window.onunhandledrejection;
  window.onunhandledrejection = (event) => {
    if (testConfig.debugMode) {
      originalConsole.error('Unhandled promise rejection:', event.reason);
    }
    return originalOnUnhandledRejection ? originalOnUnhandledRejection.call(window, event) : false;
  };

  // Jest specific error handling
  process.on('uncaughtException', (error) => {
    originalConsole.error('Uncaught exception in test:', error);
  });

  process.on('unhandledRejection', (reason, promise) => {
    originalConsole.error('Unhandled rejection in test:', reason);
  });
};

// Test performance monitoring
const setupPerformanceMonitoring = (): void => {
  let testStartTime: number;
  let testName: string;

  beforeEach(() => {
    testStartTime = performance.now();
    testName = expect.getState().currentTestName || 'unknown';
    
    // Reset performance utilities
    if ((global as any).testUtils?.clearConsoleBuffer) {
      (global as any).testUtils.clearConsoleBuffer();
    }
  });

  afterEach(() => {
    const testDuration = performance.now() - testStartTime;
    
    if (testDuration > testConfig.performanceThreshold) {
      console.warn(
        `⚠️  Slow test detected: "${testName}" took ${testDuration.toFixed(2)}ms (threshold: ${testConfig.performanceThreshold}ms)`
      );
    }
    
    // Check for console errors
    const errors = (global as any).testUtils?.getConsoleOutput('error') || [];
    if (errors.length > 0 && testConfig.debugMode) {
      console.warn(`⚠️  Test "${testName}" had ${errors.length} console errors`);
    }
  });
};

// Memory leak detection
const setupMemoryLeakDetection = (): void => {
  let initialMemory: number;

  beforeAll(() => {
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    initialMemory = process.memoryUsage().heapUsed;
  });

  afterAll(() => {
    // Force garbage collection
    if (global.gc) {
      global.gc();
    }
    
    const finalMemory = process.memoryUsage().heapUsed;
    const memoryDelta = finalMemory - initialMemory;
    
    if (memoryDelta > testConfig.memoryThreshold) {
      console.warn(
        `⚠️  Memory leak detected: ${(memoryDelta / 1024 / 1024).toFixed(2)}MB increase ` +
        `(threshold: ${(testConfig.memoryThreshold / 1024 / 1024).toFixed(2)}MB)`
      );
    }
  });
};

// Test data cleanup
const setupCleanup = (): void => {
  afterEach(() => {
    // Clear all mocks
    jest.clearAllMocks();
    
    // Clear timers
    jest.clearAllTimers();
    
    // Reset DOM
    document.body.innerHTML = '';
    
    // Clear local/session storage
    window.localStorage.clear();
    window.sessionStorage.clear();
    
    // Reset URL
    if (window.history?.replaceState) {
      window.history.replaceState(null, '', '/');
    }
  });

  beforeEach(() => {
    // Ensure clean state
    jest.restoreAllMocks();
  });
};

// Debug utilities
const setupDebugUtilities = (): void => {
  if (testConfig.debugMode) {
    (global as any).debug = {
      config: testConfig,
      dumpConsoleBuffer: () => {
        console.log('=== Console Buffer ===');
        consoleBuffer.forEach(entry => {
          console.log(`[${entry.type.toUpperCase()}] ${new Date(entry.timestamp).toISOString()}:`, ...entry.args);
        });
        console.log('=== End Console Buffer ===');
      },
      memoryUsage: () => {
        const usage = process.memoryUsage();
        console.log('Memory Usage:', {
          rss: `${(usage.rss / 1024 / 1024).toFixed(2)}MB`,
          heapTotal: `${(usage.heapTotal / 1024 / 1024).toFixed(2)}MB`,
          heapUsed: `${(usage.heapUsed / 1024 / 1024).toFixed(2)}MB`,
          external: `${(usage.external / 1024 / 1024).toFixed(2)}MB`,
        });
      },
    };
  }
};

// Main setup function
const setupTestEnvironment = (): void => {
  // Core setup
  setupDOMMocks();
  setupTestUtilities();
  setupErrorHandling();
  setupPerformanceMonitoring();
  setupMemoryLeakDetection();
  setupCleanup();
  setupDebugUtilities();
  
  // Framework-specific setup
  setupPerformanceTesting();
  setupWebSocketTesting();
  
  if (testConfig.debugMode) {
    console.log('🧪 Enhanced test environment initialized');
    console.log('Test Config:', testConfig);
  }
};

// Initialize test environment
setupTestEnvironment();

// Export configuration for external access
export { testConfig };
export default setupTestEnvironment;