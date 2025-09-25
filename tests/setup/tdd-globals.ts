/**
 * TDD Global Setup
 * Global configurations and polyfills for TDD environment
 */

import 'whatwg-fetch';
import { TextEncoder, TextDecoder } from 'util';
import { jest } from '@jest/globals';

// Polyfills for jsdom environment
if (typeof global.TextEncoder === 'undefined') {
  global.TextEncoder = TextEncoder;
}

if (typeof global.TextDecoder === 'undefined') {
  global.TextDecoder = TextDecoder;
}

// WebSocket mock for TDD
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  public url: string;
  public readyState: number;
  public onopen?: (event: Event) => void;
  public onclose?: (event: CloseEvent) => void;
  public onmessage?: (event: MessageEvent) => void;
  public onerror?: (event: Event) => void;
  public protocol: string;
  public extensions: string;

  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.protocol = '';
    this.extensions = '';

    // Simulate connection opening
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.(new Event('open'));
    }, 0);
  }

  send(data: string | ArrayBuffer | Blob): void {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new DOMException('InvalidStateError');
    }
    // Mock implementation - can be extended for specific test needs
  }

  close(code?: number, reason?: string): void {
    this.readyState = MockWebSocket.CLOSING;
    setTimeout(() => {
      this.readyState = MockWebSocket.CLOSED;
      this.onclose?.(new CloseEvent('close', { code: code || 1000, reason: reason || '' }));
    }, 0);
  }

  addEventListener(type: string, listener: EventListener): void {
    // Mock implementation
  }

  removeEventListener(type: string, listener: EventListener): void {
    // Mock implementation
  }

  dispatchEvent(event: Event): boolean {
    return true;
  }
}

global.WebSocket = MockWebSocket as any;

// Canvas mock for terminal rendering tests
HTMLCanvasElement.prototype.getContext = jest.fn().mockImplementation((contextType) => {
  if (contextType === '2d') {
    return {
      fillRect: jest.fn(),
      clearRect: jest.fn(),
      getImageData: jest.fn(() => ({
        data: new Uint8ClampedArray(4),
      })),
      putImageData: jest.fn(),
      createImageData: jest.fn(() => ({})),
      setTransform: jest.fn(),
      drawImage: jest.fn(),
      save: jest.fn(),
      fillText: jest.fn(),
      restore: jest.fn(),
      beginPath: jest.fn(),
      moveTo: jest.fn(),
      lineTo: jest.fn(),
      closePath: jest.fn(),
      stroke: jest.fn(),
      translate: jest.fn(),
      scale: jest.fn(),
      rotate: jest.fn(),
      arc: jest.fn(),
      fill: jest.fn(),
      measureText: jest.fn(() => ({ width: 0 })),
      transform: jest.fn(),
      rect: jest.fn(),
      clip: jest.fn(),
    };
  }
  return null;
});

// Media query mock
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

// Clipboard API mock
Object.defineProperty(navigator, 'clipboard', {
  writable: true,
  value: {
    writeText: jest.fn().mockImplementation(() => Promise.resolve()),
    readText: jest.fn().mockImplementation(() => Promise.resolve('')),
    write: jest.fn().mockImplementation(() => Promise.resolve()),
    read: jest.fn().mockImplementation(() => Promise.resolve([])),
  },
});

// File API mocks
global.File = class MockFile {
  constructor(
    public bits: BlobPart[],
    public name: string,
    public options: FilePropertyBag = {}
  ) {}

  get size() { return 0; }
  get type() { return this.options.type || ''; }
  get lastModified() { return this.options.lastModified || Date.now(); }

  arrayBuffer() { return Promise.resolve(new ArrayBuffer(0)); }
  slice() { return new MockFile([], ''); }
  stream() { return new ReadableStream(); }
  text() { return Promise.resolve(''); }
};

global.FileReader = class MockFileReader extends EventTarget {
  result: string | ArrayBuffer | null = null;
  error: any = null;
  readyState = 0;

  readAsText() {
    setTimeout(() => {
      this.result = '';
      this.readyState = 2;
      this.dispatchEvent(new Event('load'));
    }, 0);
  }

  readAsDataURL() {
    setTimeout(() => {
      this.result = 'data:text/plain;base64,';
      this.readyState = 2;
      this.dispatchEvent(new Event('load'));
    }, 0);
  }

  readAsArrayBuffer() {
    setTimeout(() => {
      this.result = new ArrayBuffer(0);
      this.readyState = 2;
      this.dispatchEvent(new Event('load'));
    }, 0);
  }

  abort() {
    this.readyState = 2;
    this.dispatchEvent(new Event('abort'));
  }

  onload: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onabort: ((event: Event) => void) | null = null;
  onloadstart: ((event: Event) => void) | null = null;
  onloadend: ((event: Event) => void) | null = null;
  onprogress: ((event: Event) => void) | null = null;
};

// Storage mocks with proper implementation
const mockStorage = () => ({
  getItem: jest.fn((key: string) => null),
  setItem: jest.fn((key: string, value: string) => {}),
  removeItem: jest.fn((key: string) => {}),
  clear: jest.fn(() => {}),
  key: jest.fn((index: number) => null),
  get length() { return 0; },
});

Object.defineProperty(window, 'localStorage', {
  writable: true,
  value: mockStorage(),
});

Object.defineProperty(window, 'sessionStorage', {
  writable: true,
  value: mockStorage(),
});

// URL API mock
global.URL.createObjectURL = jest.fn(() => 'mock-url');
global.URL.revokeObjectURL = jest.fn();

// Crypto API mock
Object.defineProperty(global, 'crypto', {
  writable: true,
  value: {
    getRandomValues: jest.fn((array: Uint8Array) => {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
      return array;
    }),
    randomUUID: jest.fn(() => 'mock-uuid-' + Math.random().toString(36).substr(2, 9)),
    subtle: {
      digest: jest.fn(() => Promise.resolve(new ArrayBuffer(32))),
      encrypt: jest.fn(() => Promise.resolve(new ArrayBuffer(16))),
      decrypt: jest.fn(() => Promise.resolve(new ArrayBuffer(16))),
      sign: jest.fn(() => Promise.resolve(new ArrayBuffer(64))),
      verify: jest.fn(() => Promise.resolve(true)),
      generateKey: jest.fn(() => Promise.resolve({})),
      importKey: jest.fn(() => Promise.resolve({})),
      exportKey: jest.fn(() => Promise.resolve(new ArrayBuffer(32))),
    },
  },
});

// Request/Response mocks for fetch
global.Request = class MockRequest {
  constructor(public url: string, public options: RequestInit = {}) {}
  clone() { return new MockRequest(this.url, this.options); }
  arrayBuffer() { return Promise.resolve(new ArrayBuffer(0)); }
  blob() { return Promise.resolve(new Blob()); }
  json() { return Promise.resolve({}); }
  text() { return Promise.resolve(''); }
  formData() { return Promise.resolve(new FormData()); }
} as any;

global.Response = class MockResponse {
  constructor(public body?: BodyInit, public options: ResponseInit = {}) {}
  clone() { return new MockResponse(this.body, this.options); }
  arrayBuffer() { return Promise.resolve(new ArrayBuffer(0)); }
  blob() { return Promise.resolve(new Blob()); }
  json() { return Promise.resolve({}); }
  text() { return Promise.resolve(''); }
  formData() { return Promise.resolve(new FormData()); }
  get ok() { return true; }
  get status() { return 200; }
  get statusText() { return 'OK'; }
  get headers() { return new Headers(); }
} as any;

// Headers mock
global.Headers = class MockHeaders {
  private headers = new Map<string, string>();

  append(name: string, value: string) { this.headers.set(name.toLowerCase(), value); }
  delete(name: string) { this.headers.delete(name.toLowerCase()); }
  get(name: string) { return this.headers.get(name.toLowerCase()) || null; }
  has(name: string) { return this.headers.has(name.toLowerCase()); }
  set(name: string, value: string) { this.headers.set(name.toLowerCase(), value); }

  *entries() { yield* this.headers.entries(); }
  *keys() { yield* this.headers.keys(); }
  *values() { yield* this.headers.values(); }

  forEach(callback: (value: string, key: string) => void) {
    this.headers.forEach(callback);
  }
} as any;

// FormData mock
global.FormData = class MockFormData {
  private data = new Map<string, string | File>();

  append(name: string, value: string | Blob, fileName?: string) {
    this.data.set(name, value as string | File);
  }

  delete(name: string) { this.data.delete(name); }
  get(name: string) { return this.data.get(name) || null; }
  getAll(name: string) { return this.data.has(name) ? [this.data.get(name)!] : []; }
  has(name: string) { return this.data.has(name); }
  set(name: string, value: string | Blob, fileName?: string) {
    this.data.set(name, value as string | File);
  }

  *entries() { yield* this.data.entries(); }
  *keys() { yield* this.data.keys(); }
  *values() { yield* this.data.values(); }

  forEach(callback: (value: FormDataEntryValue, key: string) => void) {
    this.data.forEach(callback as any);
  }
} as any;

// Environment variables for TDD
process.env.NODE_ENV = 'test';
process.env.TDD_MODE = 'true';

// Set up test-specific timeouts
if (typeof global.setTimeout === 'function') {
  global.setTimeout = jest.fn(global.setTimeout);
  global.clearTimeout = jest.fn(global.clearTimeout);
  global.setInterval = jest.fn(global.setInterval);
  global.clearInterval = jest.fn(global.clearInterval);
}

// Console overrides for cleaner test output
const originalWarn = console.warn;
console.warn = (...args: any[]) => {
  // Filter out specific warnings that clutter test output
  const message = args[0];
  if (typeof message === 'string') {
    if (
      message.includes('Failed prop type') ||
      message.includes('componentWillMount') ||
      message.includes('componentWillReceiveProps')
    ) {
      return;
    }
  }
  originalWarn(...args);
};

export {};