/**
 * Test Mock Factories for Claude UI Terminal Application
 * 
 * Comprehensive mocking strategies for WebSocket, Terminal, and State testing
 */

// import { vi } from 'vitest';
import type { TerminalSession, WebSocketMessage, AppState } from '@/types';

// ============================================================================
// WebSocket Mock Factory
// ============================================================================

export interface MockWebSocketOptions {
  url?: string;
  readyState?: number;
  simulateLatency?: number;
  autoConnect?: boolean;
  enableLogging?: boolean;
}

export class MockWebSocket implements WebSocket {
  public static readonly CONNECTING = 0;
  public static readonly OPEN = 1;
  public static readonly CLOSING = 2;
  public static readonly CLOSED = 3;

  // Instance properties to satisfy WebSocket interface
  public readonly CONNECTING = 0;
  public readonly OPEN = 1;
  public readonly CLOSING = 2;
  public readonly CLOSED = 3;

  public readyState: number;
  public url: string;
  public protocol = '';
  public extensions = '';
  public bufferedAmount = 0;
  public binaryType: BinaryType = 'blob';

  public onopen: ((event: Event) => void) | null = null;
  public onclose: ((event: CloseEvent) => void) | null = null;
  public onmessage: ((event: MessageEvent) => void) | null = null;
  public onerror: ((event: Event) => void) | null = null;

  private messageQueue: any[] = [];
  private eventListeners: Map<string, Function[]> = new Map();
  private options: MockWebSocketOptions;
  private timeouts: NodeJS.Timeout[] = [];

  constructor(url: string, options: MockWebSocketOptions = {}) {
    this.url = url;
    this.options = {
      readyState: MockWebSocket.CONNECTING,
      simulateLatency: 0,
      autoConnect: true,
      enableLogging: false,
      ...options
    };
    
    this.readyState = this.options.readyState!;
    
    if (this.options.autoConnect) {
      this.simulateConnection();
    }
  }

  // Standard WebSocket methods
  send(data: string | ArrayBufferLike | Blob | ArrayBufferView): void {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }

    const message = typeof data === 'string' ? JSON.parse(data) : data;
    this.messageQueue.push(message);
    
    if (this.options.enableLogging) {
      console.log('[MockWebSocket] Message sent:', message);
    }

    // Simulate server echo for testing
    this.simulateServerResponse(message);
  }

  close(code?: number, reason?: string): void {
    this.readyState = MockWebSocket.CLOSING;
    setTimeout(() => {
      this.readyState = MockWebSocket.CLOSED;
      const closeEvent = new CloseEvent('close', { code, reason });
      this.onclose?.(closeEvent);
      this.dispatchEvent(closeEvent);
    }, 10);
  }

  addEventListener(type: string, listener: EventListener): void {
    if (!this.eventListeners.has(type)) {
      this.eventListeners.set(type, []);
    }
    this.eventListeners.get(type)!.push(listener);
  }

  removeEventListener(type: string, listener: EventListener): void {
    const listeners = this.eventListeners.get(type);
    if (listeners) {
      const index = listeners.indexOf(listener);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    }
  }

  dispatchEvent(event: Event): boolean {
    const listeners = this.eventListeners.get(event.type) || [];
    listeners.forEach(listener => listener(event));
    return true;
  }

  // Test utility methods
  public simulateConnection(): void {
    const delay = this.options.simulateLatency || 0;
    const timeout = setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      const openEvent = new Event('open');
      this.onopen?.(openEvent);
      this.dispatchEvent(openEvent);
    }, delay);
    this.timeouts.push(timeout);
  }

  public simulateConnectionError(): void {
    this.readyState = MockWebSocket.CLOSED;
    const errorEvent = new Event('error');
    this.onerror?.(errorEvent);
    this.dispatchEvent(errorEvent);
  }

  public simulateServerMessage(data: any): void {
    if (this.readyState !== MockWebSocket.OPEN) return;

    const messageEvent = new MessageEvent('message', {
      data: typeof data === 'string' ? data : JSON.stringify(data)
    });
    
    const delay = this.options.simulateLatency || 0;
    const timeout = setTimeout(() => {
      this.onmessage?.(messageEvent);
      this.dispatchEvent(messageEvent);
    }, delay);
    this.timeouts.push(timeout);
  }

  public simulateNetworkInterruption(duration: number = 1000): void {
    this.readyState = MockWebSocket.CLOSED;
    const closeEvent = new CloseEvent('close', { code: 1006, reason: 'Network interruption' });
    this.onclose?.(closeEvent);
    this.dispatchEvent(closeEvent);

    // Simulate reconnection after duration
    const timeout = setTimeout(() => {
      this.simulateConnection();
    }, duration);
    this.timeouts.push(timeout);
  }

  public getMessageHistory(): any[] {
    return [...this.messageQueue];
  }

  public clearMessageHistory(): void {
    this.messageQueue = [];
  }

  public cleanup(): void {
    this.timeouts.forEach(timeout => clearTimeout(timeout));
    this.timeouts = [];
    this.eventListeners.clear();
  }

  private simulateServerResponse(message: any): void {
    // Simulate different server responses based on message type
    switch (message.type) {
      case 'create':
        this.simulateServerMessage({
          type: 'session_created',
          data: { sessionId: `session-${Date.now()}` }
        });
        break;
      case 'data':
        this.simulateServerMessage({
          type: 'output',
          data: { sessionId: message.data.sessionId, output: `Echo: ${message.data.data}` }
        });
        break;
      case 'resize':
        this.simulateServerMessage({
          type: 'resize_ack',
          data: { sessionId: message.data.sessionId, cols: message.data.cols, rows: message.data.rows }
        });
        break;
    }
  }
}

// ============================================================================
// Terminal Mock Factory
// ============================================================================

export interface MockTerminalOptions {
  cols?: number;
  rows?: number;
  enableEvents?: boolean;
}

export class MockTerminal {
  public cols: number;
  public rows: number;
  public element: HTMLElement | null = null;
  
  private eventListeners: Map<string, Function[]> = new Map();
  private writeBuffer: string[] = [];
  private options: MockTerminalOptions;

  constructor(options: MockTerminalOptions = {}) {
    this.options = {
      cols: 80,
      rows: 24,
      enableEvents: true,
      ...options
    };
    
    this.cols = this.options.cols!;
    this.rows = this.options.rows!;
  }

  // Terminal methods
  open(parent: HTMLElement): void {
    this.element = parent;
    // Simulate terminal opening
  }

  write(data: string): void {
    this.writeBuffer.push(data);
  }

  writeln(data: string): void {
    this.write(data + '\n');
  }

  clear(): void {
    this.writeBuffer = [];
  }

  focus(): void {
    // Simulate focus
  }

  blur(): void {
    // Simulate blur
  }

  dispose(): void {
    this.element = null;
    this.eventListeners.clear();
    this.writeBuffer = [];
  }

  onData(listener: (data: string) => void): { dispose: () => void } {
    if (!this.eventListeners.has('data')) {
      this.eventListeners.set('data', []);
    }
    this.eventListeners.get('data')!.push(listener);
    
    return {
      dispose: () => {
        const listeners = this.eventListeners.get('data');
        if (listeners) {
          const index = listeners.indexOf(listener);
          if (index > -1) {
            listeners.splice(index, 1);
          }
        }
      }
    };
  }

  onResize(listener: (size: { cols: number; rows: number }) => void): { dispose: () => void } {
    if (!this.eventListeners.has('resize')) {
      this.eventListeners.set('resize', []);
    }
    this.eventListeners.get('resize')!.push(listener);
    
    return {
      dispose: () => {
        const listeners = this.eventListeners.get('resize');
        if (listeners) {
          const index = listeners.indexOf(listener);
          if (index > -1) {
            listeners.splice(index, 1);
          }
        }
      }
    };
  }

  // Test utility methods
  public simulateUserInput(data: string): void {
    const listeners = this.eventListeners.get('data') || [];
    listeners.forEach(listener => listener(data));
  }

  public simulateResize(cols: number, rows: number): void {
    this.cols = cols;
    this.rows = rows;
    const listeners = this.eventListeners.get('resize') || [];
    listeners.forEach(listener => listener({ cols, rows }));
  }

  public getWriteBuffer(): string[] {
    return [...this.writeBuffer];
  }

  public getLastWrite(): string | undefined {
    return this.writeBuffer[this.writeBuffer.length - 1];
  }

  public clearWriteBuffer(): void {
    this.writeBuffer = [];
  }
}

// ============================================================================
// Session Data Factory
// ============================================================================

export const createMockSession = (overrides: Partial<TerminalSession> = {}): TerminalSession => ({
  id: `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  name: `Test Terminal ${Math.floor(Math.random() * 100)}`,
  isActive: true,
  lastActivity: new Date(),
  ...overrides
});

export const createMultipleMockSessions = (count: number): TerminalSession[] => {
  return Array.from({ length: count }, (_, index) => 
    createMockSession({
      name: `Terminal ${index + 1}`,
      isActive: index === 0 // First session is active
    })
  );
};

// ============================================================================
// WebSocket Message Factory
// ============================================================================

export const createMockWebSocketMessage = (
  type: "data" | "list" | "resize" | "create" | "destroy", 
  data: any = {}, 
  overrides: Partial<WebSocketMessage> = {}
): WebSocketMessage => ({
  type,
  data,
  id: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  ...overrides
} as WebSocketMessage);

export const createTerminalOutputMessage = (sessionId: string, output: string) =>
  createMockWebSocketMessage('data', { sessionId, output });

export const createSessionCreatedMessage = (sessionId: string) =>
  createMockWebSocketMessage('create', { sessionId });

export const createErrorMessage = (error: string, code?: number) =>
  createMockWebSocketMessage('data', { error, code });

// ============================================================================
// Store State Factory
// ============================================================================

export const createMockAppState = (overrides: Partial<AppState> = {}): AppState => ({
  terminalSessions: [],
  activeSessionId: null,
  sidebarOpen: true,
  loading: false,
  error: null,
  ...overrides
});

export const createMockStoreWithSessions = (sessionCount: number = 3): AppState => {
  const sessions = createMultipleMockSessions(sessionCount);
  return createMockAppState({
    terminalSessions: sessions,
    activeSessionId: sessions[0]?.id || null
  });
};

// ============================================================================
// Performance Test Data Factory
// ============================================================================

export const createLargeTerminalOutput = (sizeKB: number): string => {
  const chunkSize = 1024; // 1KB chunks
  const chunks = Math.ceil(sizeKB);
  
  return Array.from({ length: chunks }, (_, i) => 
    `Line ${i + 1}: ${'x'.repeat(chunkSize - 20)}\n`
  ).join('');
};

export const createHighFrequencyMessages = (count: number, sessionId: string): WebSocketMessage[] => {
  return Array.from({ length: count }, (_, i) => 
    createTerminalOutputMessage(sessionId, `Message ${i + 1}: ${Date.now()}`)
  );
};

// ============================================================================
// Error Simulation Factory
// ============================================================================

export class ErrorSimulator {
  static createNetworkError(): Error {
    const error = new Error('Network request failed');
    error.name = 'NetworkError';
    return error;
  }

  static createWebSocketError(code: number = 1006): CloseEvent {
    return new CloseEvent('close', { 
      code, 
      reason: 'Connection failed',
      wasClean: false 
    });
  }

  static createTerminalError(): Error {
    const error = new Error('Terminal initialization failed');
    error.name = 'TerminalError';
    return error;
  }

  static createParsingError(): Error {
    const error = new Error('Failed to parse WebSocket message');
    error.name = 'SyntaxError';
    return error;
  }

  static createTimeoutError(): Error {
    const error = new Error('Operation timed out');
    error.name = 'TimeoutError';
    return error;
  }
}

// ============================================================================
// Test Environment Setup Utilities
// ============================================================================

export const setupTestEnvironment = () => {
  // Mock global objects
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  }));

  // Mock WebSocket constructor
  global.WebSocket = MockWebSocket as any;
  
  // Mock performance API
  global.performance = {
    ...global.performance,
    now: jest.fn(() => Date.now()),
    mark: jest.fn(),
    measure: jest.fn(),
  };
  
  // Mock navigation APIs
  Object.defineProperty(window, 'navigator', {
    value: {
      userAgent: 'test-agent',
      onLine: true,
    },
    writable: true,
  });
};

export const teardownTestEnvironment = () => {
  jest.restoreAllMocks();
  jest.clearAllTimers();
};

// ============================================================================
// Test Assertion Helpers
// ============================================================================

export const expectWebSocketMessage = (mock: MockWebSocket, type: string, data?: any) => {
  const messages = mock.getMessageHistory();
  const matchingMessage = messages.find(msg => msg.type === type);
  
  expect(matchingMessage).toBeDefined();
  if (data) {
    expect(matchingMessage.data).toMatchObject(data);
  }
  
  return matchingMessage;
};

export const expectTerminalWrite = (mock: MockTerminal, expectedText: string) => {
  const buffer = mock.getWriteBuffer();
  const hasText = buffer.some(write => write.includes(expectedText));
  expect(hasText).toBe(true);
};

export const waitForAsyncOperation = (ms: number = 100): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

export const waitForCondition = async (
  condition: () => boolean,
  timeout: number = 5000,
  interval: number = 100
): Promise<void> => {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    if (condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  throw new Error(`Condition not met within ${timeout}ms`);
};