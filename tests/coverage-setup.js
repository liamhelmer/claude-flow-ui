/**
 * Coverage-specific Jest setup
 * Ensures optimal coverage collection and reporting
 */

// Global setup for coverage testing
beforeAll(() => {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.COVERAGE = 'true';

  // Mock console methods to reduce noise in coverage reports
  global.console = {
    ...console,
    // Uncomment to silence logs during coverage
    // log: jest.fn(),
    // debug: jest.fn(),
    // info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  };
});

// Clean up after all tests for accurate coverage
afterAll(() => {
  // Clean up any global state
  jest.clearAllMocks();
  jest.resetAllMocks();
  jest.restoreAllMocks();
});

// Global error handler for unhandled promises
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Coverage-specific mocks and stubs
global.mockImplementations = {
  // Mock DOM APIs that might not be available in Node
  window: {
    location: {
      href: 'http://localhost:3000',
      origin: 'http://localhost:3000',
      pathname: '/',
      search: '',
      hash: ''
    },
    document: {
      title: 'Test Document',
      createElement: jest.fn(),
      getElementById: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn()
    },
    navigator: {
      userAgent: 'Test User Agent',
      platform: 'Test Platform'
    },
    localStorage: {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn()
    },
    sessionStorage: {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn()
    }
  }
};

// Mock fetch for API calls
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(''),
    blob: () => Promise.resolve(new Blob()),
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0))
  })
);

// Mock WebSocket for real-time connections
global.WebSocket = jest.fn(() => ({
  readyState: 1, // OPEN
  send: jest.fn(),
  close: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  onopen: null,
  onclose: null,
  onmessage: null,
  onerror: null
}));

// Mock IntersectionObserver for component visibility testing
global.IntersectionObserver = jest.fn(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn()
}));

// Mock ResizeObserver for responsive component testing
global.ResizeObserver = jest.fn(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn()
}));

// Mock performance API
global.performance = {
  ...global.performance,
  now: jest.fn(() => Date.now()),
  mark: jest.fn(),
  measure: jest.fn(),
  getEntriesByType: jest.fn(() => []),
  getEntriesByName: jest.fn(() => [])
};

// Mock requestAnimationFrame
global.requestAnimationFrame = jest.fn(cb => setTimeout(cb, 16));
global.cancelAnimationFrame = jest.fn(id => clearTimeout(id));

// Helper to reset all mocks between tests
global.resetAllMocks = () => {
  jest.clearAllMocks();
  jest.resetAllMocks();
  jest.restoreAllMocks();
};

// Coverage helper functions
global.coverageHelpers = {
  // Helper to test all branches of a conditional
  testAllBranches: (fn, testCases) => {
    testCases.forEach(testCase => {
      try {
        fn(testCase.input);
      } catch (error) {
        if (!testCase.shouldThrow) {
          throw error;
        }
      }
    });
  },

  // Helper to test error boundaries
  testErrorBoundary: (Component, errorTrigger) => {
    const originalError = console.error;
    console.error = jest.fn();

    try {
      errorTrigger();
    } finally {
      console.error = originalError;
    }
  },

  // Helper to test async functions with timeouts
  testWithTimeout: async (fn, timeout = 5000) => {
    return Promise.race([
      fn(),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Test timeout')), timeout)
      )
    ]);
  }
};