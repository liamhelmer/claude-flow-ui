/**
 * Reliable Jest Setup for setupFiles (runs before Jest environment)
 * Optimized for stability and performance - minimal dependencies
 */

// Environment setup only - no Jest globals here
process.env.NODE_ENV = 'test';
process.env.NEXT_PUBLIC_WS_PORT = '11237';
process.env.NEXT_PUBLIC_WS_URL = 'ws://localhost:11237';

// Minimal WebSocket mock to prevent errors
global.WebSocket = class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.onopen = null;
    this.onclose = null;
    this.onerror = null;
    this.onmessage = null;
    
    // Immediate connection for test reliability
    Promise.resolve().then(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    });
  }

  send(data) {
    // Silent implementation
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close'));
    }
  }

  addEventListener(type, listener) {
    this['on' + type] = listener;
  }

  removeEventListener(type, listener) {
    this['on' + type] = null;
  }
};

// Essential browser API mocks with minimal implementation
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

global.IntersectionObserver = class IntersectionObserver {
  constructor(callback, options) {
    this.callback = callback;
    this.options = options;
  }
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return []; }
};

// Basic Canvas mock
if (typeof HTMLCanvasElement !== 'undefined') {
  HTMLCanvasElement.prototype.getContext = () => ({
    fillRect: () => {},
    clearRect: () => {},
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
    putImageData: () => {},
    measureText: () => ({ width: 10, height: 12 }),
    // Add other essential canvas methods as minimal no-ops
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    stroke: () => {},
    fill: () => {}
  });
}

// Prevent common test errors
if (typeof window !== 'undefined') {
  // Match media mock
  if (!window.matchMedia) {
    window.matchMedia = (query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => {}
    });
  }

  // Performance mock basics
  if (!window.performance) {
    window.performance = {
      now: () => Date.now(),
      timeOrigin: Date.now()
    };
  }
}

console.log('✅ Reliable Jest setup completed');