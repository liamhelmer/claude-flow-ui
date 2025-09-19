/**
 * Production Environment Polyfills
 *
 * Polyfills and mocks that simulate production browser environment
 * for terminal regression testing.
 */

// Mock production WebSocket with realistic behavior
global.WebSocket = class ProductionWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.readyState = ProductionWebSocket.CONNECTING;
    this.onopen = null;
    this.onclose = null;
    this.onmessage = null;
    this.onerror = null;

    // Simulate production connection timing
    setTimeout(() => {
      this.readyState = ProductionWebSocket.OPEN;
      if (this.onopen) {
        this.onopen({ type: 'open', target: this });
      }
    }, 50 + Math.random() * 50); // 50-100ms delay
  }

  send(data) {
    if (this.readyState !== ProductionWebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }

    // Simulate production message processing
    setTimeout(() => {
      if (this.onmessage && this.readyState === ProductionWebSocket.OPEN) {
        this.onmessage({
          type: 'message',
          data: data,
          target: this
        });
      }
    }, 10 + Math.random() * 20); // 10-30ms delay
  }

  close(code = 1000, reason = '') {
    if (this.readyState === ProductionWebSocket.CLOSED) return;

    this.readyState = ProductionWebSocket.CLOSING;

    setTimeout(() => {
      this.readyState = ProductionWebSocket.CLOSED;
      if (this.onclose) {
        this.onclose({
          type: 'close',
          code: code,
          reason: reason,
          wasClean: code === 1000,
          target: this
        });
      }
    }, 30);
  }
};

// Mock production-specific DOM APIs
Object.defineProperty(window, 'requestIdleCallback', {
  value: function(callback, options = {}) {
    const timeout = options.timeout || 5000;
    const deadline = performance.now() + 16.67; // ~60fps

    return setTimeout(() => {
      callback({
        didTimeout: false,
        timeRemaining: () => Math.max(0, deadline - performance.now())
      });
    }, 16);
  },
  writable: true
});

Object.defineProperty(window, 'cancelIdleCallback', {
  value: function(handle) {
    clearTimeout(handle);
  },
  writable: true
});

// Mock IntersectionObserver for production behavior
global.IntersectionObserver = class IntersectionObserver {
  constructor(callback, options = {}) {
    this.callback = callback;
    this.options = options;
    this.entries = [];
  }

  observe(element) {
    // Simulate production observation timing
    setTimeout(() => {
      this.callback([{
        target: element,
        isIntersecting: true,
        intersectionRatio: 1,
        boundingClientRect: element.getBoundingClientRect(),
        rootBounds: null,
        time: performance.now()
      }]);
    }, 100);
  }

  unobserve(element) {
    // No-op in mock
  }

  disconnect() {
    this.entries = [];
  }
};

// Mock ResizeObserver for production behavior
global.ResizeObserver = class ResizeObserver {
  constructor(callback) {
    this.callback = callback;
  }

  observe(element) {
    // Simulate production resize observation
    setTimeout(() => {
      this.callback([{
        target: element,
        contentRect: {
          width: element.offsetWidth || 800,
          height: element.offsetHeight || 600,
          top: 0,
          left: 0,
          bottom: element.offsetHeight || 600,
          right: element.offsetWidth || 800
        }
      }]);
    }, 50);
  }

  unobserve(element) {
    // No-op in mock
  }

  disconnect() {
    // No-op in mock
  }
};

// Mock production console behavior
const originalConsole = { ...console };

// In production, debug and trace are often disabled
console.debug = () => {};
console.trace = () => {};

// Log messages might be rate-limited in production
let logCount = 0;
const originalLog = console.log;
console.log = (...args) => {
  logCount++;
  if (logCount <= 100) { // Simulate production log limits
    originalLog(...args);
  }
};

// Mock production localStorage with size limits
const originalLocalStorage = { ...localStorage };
let storageSize = 0;
const MAX_STORAGE = 5 * 1024 * 1024; // 5MB limit

Storage.prototype.setItem = function(key, value) {
  const size = new Blob([key + value]).size;

  if (storageSize + size > MAX_STORAGE) {
    throw new Error('QuotaExceededError: localStorage quota exceeded');
  }

  storageSize += size;
  return originalLocalStorage.setItem.call(this, key, value);
};

// Mock production fetch with network delays
const originalFetch = global.fetch;
global.fetch = function(...args) {
  return new Promise((resolve, reject) => {
    // Simulate production network latency
    const delay = 100 + Math.random() * 200; // 100-300ms

    setTimeout(() => {
      if (originalFetch) {
        originalFetch(...args).then(resolve).catch(reject);
      } else {
        // Fallback mock response
        resolve(new Response('{}', {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        }));
      }
    }, delay);
  });
};

// Export production markers for test verification
global.PRODUCTION_TEST_MARKERS = {
  webSocketMocked: true,
  consoleLimited: true,
  networkDelayEnabled: true,
  storageQuotaEnabled: true,
  intersectionObserverMocked: true,
  resizeObserverMocked: true
};