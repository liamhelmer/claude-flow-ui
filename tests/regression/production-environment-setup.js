/**
 * Production Environment Setup for Terminal Testing
 *
 * This setup file explicitly configures the test environment to match
 * production conditions where terminal input/switching issues occur.
 */

// Force production environment
process.env.NODE_ENV = 'production';

// Disable development-specific optimizations
process.env.FAST_REFRESH = 'false';
process.env.REACT_STRICT_MODE = 'false';

// Mock production-specific global configurations
global.console = {
  ...console,
  // In production, some console methods might be disabled/reduced
  debug: () => {}, // Commonly disabled in production
  trace: () => {}, // Often disabled in production
  log: (...args) => {
    // Only log in test environment to avoid noise
    if (process.env.JEST_WORKER_ID) {
      console.log(...args);
    }
  }
};

// Mock WebSocket for production-like behavior
class MockWebSocketProduction {
  constructor(url) {
    this.url = url;
    this.readyState = WebSocket.CONNECTING;
    this.onopen = null;
    this.onclose = null;
    this.onmessage = null;
    this.onerror = null;

    // Simulate production connection delays
    setTimeout(() => {
      this.readyState = WebSocket.OPEN;
      if (this.onopen) this.onopen();
    }, 100);
  }

  send(data) {
    // In production, there might be slight delays in message processing
    setTimeout(() => {
      if (this.onmessage) {
        this.onmessage({
          data: JSON.stringify({
            type: 'terminal_output',
            sessionId: 'test-session',
            data: data
          })
        });
      }
    }, 50);
  }

  close() {
    this.readyState = WebSocket.CLOSED;
    if (this.onclose) this.onclose();
  }
}

// Mock production WebSocket behavior
global.WebSocket = MockWebSocketProduction;

// Mock production-specific DOM behaviors
Object.defineProperty(window, 'requestIdleCallback', {
  value: (callback) => {
    // In production, requestIdleCallback might behave differently
    setTimeout(callback, 16); // Simulate frame timing
  }
});

// Mock production event listener behavior
const originalAddEventListener = Element.prototype.addEventListener;
Element.prototype.addEventListener = function(type, listener, options) {
  // In production, event listeners might have different timing
  if (type === 'input' || type === 'keydown' || type === 'keyup') {
    // Add slight delay to simulate production event handling
    const delayedListener = function(event) {
      setTimeout(() => listener.call(this, event), 10);
    };
    return originalAddEventListener.call(this, type, delayedListener, options);
  }
  return originalAddEventListener.call(this, type, listener, options);
};

// Export utilities for tests
export const ProductionTestUtils = {
  simulateProductionDelay: (ms = 50) => new Promise(resolve => setTimeout(resolve, ms)),

  waitForAsyncUpdates: async () => {
    // In production, React updates might be batched differently
    await new Promise(resolve => setTimeout(resolve, 100));
  },

  simulateNetworkLatency: (ms = 100) => new Promise(resolve => setTimeout(resolve, ms)),

  createProductionWebSocket: (url) => new MockWebSocketProduction(url)
};

// Production-specific test environment markers
export const PRODUCTION_ENV_MARKERS = {
  NODE_ENV: 'production',
  isDevelopment: false,
  isProduction: true,
  enableDevTools: false,
  enableHotReload: false
};