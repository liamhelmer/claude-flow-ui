/**
 * Reliable Jest Setup for Claude Flow UI
 * This file provides a robust test environment setup with proper cleanup and error handling
 */

// Enhanced global test configuration
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

// Suppress known noisy warnings during tests
const suppressedWarnings = [
  'Warning: ReactDOM.render is deprecated',
  'Warning: An invalid form control',
  'Warning: componentWillReceiveProps',
  'Warning: componentWillMount',
  'Warning: componentWillUpdate',
  'The pseudo class',
  'Encountered two children with the same key',
];

// Enhanced error handling with suppression
console.error = (...args) => {
  const message = args.join(' ');
  const shouldSuppress = suppressedWarnings.some(warning => 
    message.includes(warning)
  );
  
  if (!shouldSuppress) {
    originalConsoleError.apply(console, args);
  }
};

console.warn = (...args) => {
  const message = args.join(' ');
  const shouldSuppress = suppressedWarnings.some(warning => 
    message.includes(warning)
  );
  
  if (!shouldSuppress) {
    originalConsoleWarn.apply(console, args);
  }
};

// Mock window objects that may not exist in jsdom
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
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

// Mock ResizeObserver
global.ResizeObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Mock IntersectionObserver
global.IntersectionObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Mock crypto.randomUUID for Node.js compatibility
if (!global.crypto) {
  global.crypto = {};
}
if (!global.crypto.randomUUID) {
  global.crypto.randomUUID = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  };
}

// Mock navigator.userAgent if not present
if (!global.navigator) {
  global.navigator = {};
}
if (!global.navigator.userAgent) {
  global.navigator.userAgent = 'Jest Test Environment';
}

// Enhanced timer management for test reliability
let activeTimers = new Set();
let activeIntervals = new Set();

const originalSetTimeout = global.setTimeout;
const originalClearTimeout = global.clearTimeout;
const originalSetInterval = global.setInterval;
const originalClearInterval = global.clearInterval;

global.setTimeout = (fn, delay, ...args) => {
  const id = originalSetTimeout(fn, delay, ...args);
  activeTimers.add(id);
  return id;
};

global.clearTimeout = (id) => {
  activeTimers.delete(id);
  return originalClearTimeout(id);
};

global.setInterval = (fn, delay, ...args) => {
  const id = originalSetInterval(fn, delay, ...args);
  activeIntervals.add(id);
  return id;
};

global.clearInterval = (id) => {
  activeIntervals.delete(id);
  return originalClearInterval(id);
};

// Cleanup function for timers
global.cleanupTimers = () => {
  activeTimers.forEach(id => originalClearTimeout(id));
  activeIntervals.forEach(id => originalClearInterval(id));
  activeTimers.clear();
  activeIntervals.clear();
};

// Mock fetch for tests
if (!global.fetch) {
  global.fetch = jest.fn(() =>
    Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve({}),
      text: () => Promise.resolve(''),
      blob: () => Promise.resolve(new Blob()),
    })
  );
}

// Mock WebSocket
if (!global.WebSocket) {
  global.WebSocket = jest.fn().mockImplementation(() => ({
    send: jest.fn(),
    close: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    readyState: 1, // OPEN
    CONNECTING: 0,
    OPEN: 1,
    CLOSING: 2,
    CLOSED: 3,
  }));
}

// Enhanced cleanup after each test
afterEach(() => {
  // Clean up timers
  global.cleanupTimers();
  
  // Clear any remaining mocks
  jest.clearAllMocks();
  
  // Clear localStorage and sessionStorage
  if (global.localStorage) {
    global.localStorage.clear();
  }
  if (global.sessionStorage) {
    global.sessionStorage.clear();
  }
  
  // Reset console methods
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
});

// Global error handler for unhandled promise rejections
const unhandledRejections = new Map();
process.on('unhandledRejection', (reason, promise) => {
  unhandledRejections.set(promise, reason);
});

process.on('rejectionHandled', (promise) => {
  unhandledRejections.delete(promise);
});

// Cleanup unhandled rejections after tests
afterAll(() => {
  if (unhandledRejections.size > 0) {
    console.warn(`${unhandledRejections.size} unhandled promise rejections detected`);
    unhandledRejections.clear();
  }
});

console.log('✅ Reliable Jest setup completed');