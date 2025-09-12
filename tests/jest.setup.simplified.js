/**
 * Simplified Jest Setup for setupFiles (runs before Jest environment)
 * This file is loaded via setupFiles, so Jest globals aren't available yet
 */

// Environment setup only - no Jest globals here
process.env.NODE_ENV = 'test';
process.env.NEXT_PUBLIC_WS_PORT = '11237';
process.env.NEXT_PUBLIC_WS_URL = 'ws://localhost:11237';

// Global mock definitions that don't use Jest globals
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
    
    // Use immediate for predictable timing
    setImmediate(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    });
  }

  send(data) {
    // Mock implementation - silent
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close'));
    }
  }

  addEventListener(type, listener) {
    if (type === 'open') this.onopen = listener;
    else if (type === 'close') this.onclose = listener;
    else if (type === 'error') this.onerror = listener;
    else if (type === 'message') this.onmessage = listener;
  }

  removeEventListener(type, listener) {
    if (type === 'open') this.onopen = null;
    else if (type === 'close') this.onclose = null;
    else if (type === 'error') this.onerror = null;
    else if (type === 'message') this.onmessage = null;
  }
};

// Browser API mocks
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

global.IntersectionObserver = class IntersectionObserver {
  root = null;
  rootMargin = '0px';
  thresholds = [0];
  
  constructor(callback, options) {
    this.callback = callback;
    this.options = options;
  }
  
  observe(target) {}
  unobserve(target) {}
  disconnect() {}
  takeRecords() { return []; }
};

// Canvas mock
const mockCanvasContext = {
  fillRect: () => {},
  clearRect: () => {},
  getImageData: () => ({ data: new Uint8ClampedArray(4) }),
  putImageData: () => {},
  createImageData: () => ({ data: new Uint8ClampedArray(4) }),
  setTransform: () => {},
  drawImage: () => {},
  save: () => {},
  restore: () => {},
  fillText: () => {},
  strokeText: () => {},
  measureText: () => ({ width: 10, height: 12 }),
  beginPath: () => {},
  moveTo: () => {},
  lineTo: () => {},
  closePath: () => {},
  stroke: () => {},
  fill: () => {},
  arc: () => {},
  rect: () => {},
  clip: () => {},
  translate: () => {},
  scale: () => {},
  rotate: () => {},
  transform: () => {},
};

if (typeof HTMLCanvasElement !== 'undefined') {
  HTMLCanvasElement.prototype.getContext = () => mockCanvasContext;
}

// Match media mock
if (typeof window !== 'undefined') {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => {},
    }),
  });
}

console.log('✅ Jest setup files completed');