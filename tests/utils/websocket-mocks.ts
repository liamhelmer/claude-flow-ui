/**
 * WebSocket Testing Utilities
 * Comprehensive mock strategies for WebSocket and Terminal dependencies
 */
import { EventEmitter } from 'events';

// Mock WebSocket Message Types
export interface MockWebSocketMessage {
  type: string;
  data: any;
  timestamp?: string;
  sessionId?: string;
}

// Mock Socket.IO Client
export class MockSocketIOClient extends EventEmitter {
  public connected: boolean = false;
  public connecting: boolean = false;
  public id?: string;
  private connectionDelay: number = 0;
  private shouldFailConnection: boolean = false;
  private messageHistory: MockWebSocketMessage[] = [];

  constructor(options: { 
    connectionDelay?: number;
    shouldFailConnection?: boolean;
    autoConnect?: boolean;
  } = {}) {
    super();
    this.connectionDelay = options.connectionDelay || 0;
    this.shouldFailConnection = options.shouldFailConnection || false;
    this.setMaxListeners(50); // Increase limit for testing
  }

  connect() {
    if (this.connected || this.connecting) return;
    
    this.connecting = true;
    
    setTimeout(() => {
      if (this.shouldFailConnection) {
        this.connecting = false;
        this.emit('connect_error', new Error('Mock connection failed'));
        return;
      }
      
      this.connected = true;
      this.connecting = false;
      this.id = 'mock-socket-' + Math.random().toString(36).substr(2, 9);
      this.emit('connect');
    }, this.connectionDelay);
  }

  disconnect() {
    if (!this.connected) return;
    
    this.connected = false;
    this.connecting = false;
    this.emit('disconnect', 'client disconnect');
    this.removeAllListeners();
  }

  emit(event: string, ...args: any[]): boolean {
    // Store messages for testing
    if (event !== 'connect' && event !== 'disconnect' && event !== 'connect_error') {
      this.messageHistory.push({
        type: event,
        data: args[0],
        timestamp: new Date().toISOString(),
      });
    }
    
    return super.emit(event, ...args);
  }

  // Mock Socket.IO methods
  on(event: string, callback: (...args: any[]) => void): this {
    return super.on(event, callback);
  }

  off(event: string, callback?: (...args: any[]) => void): this {
    if (callback) {
      return super.off(event, callback);
    } else {
      return super.removeAllListeners(event);
    }
  }

  removeAllListeners(event?: string): this {
    return super.removeAllListeners(event);
  }

  // Testing utilities
  getMessageHistory(): MockWebSocketMessage[] {
    return [...this.messageHistory];
  }

  clearMessageHistory(): void {
    this.messageHistory = [];
  }

  simulateMessage(type: string, data: any): void {
    setTimeout(() => {
      this.emit(type, data);
    }, 0);
  }

  simulateError(error: Error): void {
    setTimeout(() => {
      this.emit('error', error);
    }, 0);
  }

  simulateDisconnect(reason: string = 'transport close'): void {
    if (this.connected) {
      this.connected = false;
      this.connecting = false;
      setTimeout(() => {
        this.emit('disconnect', reason);
      }, 0);
    }
  }

  simulateReconnect(): void {
    if (!this.connected && !this.connecting) {
      this.connect();
    }
  }
}

// Mock WebSocket Client Factory
export const createMockWebSocketClient = (options: {
  connectionDelay?: number;
  shouldFailConnection?: boolean;
  enableRetry?: boolean;
} = {}) => {
  const mockSocket = new MockSocketIOClient(options);
  
  return {
    socket: mockSocket,
    connect: () => mockSocket.connect(),
    disconnect: () => mockSocket.disconnect(),
    connected: () => mockSocket.connected,
    connecting: () => mockSocket.connecting,
    send: jest.fn((event: string, data: any) => {
      if (mockSocket.connected) {
        mockSocket.emit(event, data);
      }
    }),
    sendMessage: jest.fn((message: MockWebSocketMessage) => {
      if (mockSocket.connected) {
        mockSocket.emit('message', message);
      }
    }),
    on: (event: string, callback: (...args: any[]) => void) => mockSocket.on(event, callback),
    off: (event: string, callback?: (...args: any[]) => void) => mockSocket.off(event, callback),
    
    // Testing utilities
    simulateMessage: (type: string, data: any) => mockSocket.simulateMessage(type, data),
    simulateError: (error: Error) => mockSocket.simulateError(error),
    simulateDisconnect: (reason?: string) => mockSocket.simulateDisconnect(reason),
    simulateReconnect: () => mockSocket.simulateReconnect(),
    getMessageHistory: () => mockSocket.getMessageHistory(),
    clearMessageHistory: () => mockSocket.clearMessageHistory(),
  };
};

// Terminal Session Mock
export const createMockTerminalSession = (overrides: Partial<{
  id: string;
  title: string;
  status: 'connected' | 'disconnected' | 'error';
  cols: number;
  rows: number;
  output: string[];
  config: any;
}> = {}) => ({
  id: 'mock-session-' + Math.random().toString(36).substr(2, 9),
  title: 'Mock Terminal Session',
  status: 'connected' as const,
  cols: 80,
  rows: 24,
  output: ['Welcome to mock terminal'],
  config: { cols: 80, rows: 24 },
  createdAt: new Date().toISOString(),
  lastActivity: new Date().toISOString(),
  ...overrides,
});

// WebSocket Message Builders
export const createTerminalDataMessage = (sessionId: string, data: string) => ({
  type: 'terminal-data',
  data: { sessionId, data },
  timestamp: new Date().toISOString(),
});

export const createTerminalResizeMessage = (sessionId: string, cols: number, rows: number) => ({
  type: 'terminal-resize',
  data: { sessionId, cols, rows },
  timestamp: new Date().toISOString(),
});

export const createTerminalConfigMessage = (sessionId: string, cols: number, rows: number) => ({
  type: 'terminal-config',
  data: { sessionId, cols, rows },
  timestamp: new Date().toISOString(),
});

export const createSessionCreatedMessage = (sessionId: string) => ({
  type: 'session-created',
  data: { sessionId, title: `Session ${sessionId}` },
  timestamp: new Date().toISOString(),
});

export const createSessionDestroyedMessage = (sessionId: string) => ({
  type: 'session-destroyed',
  data: { sessionId },
  timestamp: new Date().toISOString(),
});

export const createErrorMessage = (message: string, code?: string) => ({
  type: 'terminal-error',
  data: { message, code },
  timestamp: new Date().toISOString(),
});

// WebSocket Testing Utilities
export class WebSocketTestHarness {
  private mockClients: Map<string, ReturnType<typeof createMockWebSocketClient>> = new Map();
  private messageLog: MockWebSocketMessage[] = [];

  createClient(id: string, options: Parameters<typeof createMockWebSocketClient>[0] = {}) {
    const client = createMockWebSocketClient(options);
    this.mockClients.set(id, client);
    
    // Log all messages
    client.socket.on('message', (msg: MockWebSocketMessage) => {
      this.messageLog.push(msg);
    });
    
    return client;
  }

  getClient(id: string) {
    return this.mockClients.get(id);
  }

  removeClient(id: string) {
    const client = this.mockClients.get(id);
    if (client) {
      client.disconnect();
      this.mockClients.delete(id);
    }
  }

  broadcastMessage(message: MockWebSocketMessage) {
    this.mockClients.forEach(client => {
      client.simulateMessage(message.type, message.data);
    });
  }

  simulateNetworkFailure(clientIds?: string[]) {
    const targets = clientIds ? 
      clientIds.map(id => this.mockClients.get(id)).filter(Boolean) :
      Array.from(this.mockClients.values());
    
    targets.forEach(client => {
      if (client) {
        client.simulateError(new Error('Network failure'));
        client.simulateDisconnect('transport error');
      }
    });
  }

  simulateReconnection(clientIds?: string[]) {
    const targets = clientIds ? 
      clientIds.map(id => this.mockClients.get(id)).filter(Boolean) :
      Array.from(this.mockClients.values());
    
    targets.forEach(client => {
      if (client) {
        setTimeout(() => client?.simulateReconnect(), 100);
      }
    });
  }

  getMessageLog(): MockWebSocketMessage[] {
    return [...this.messageLog];
  }

  clearMessageLog(): void {
    this.messageLog = [];
  }

  cleanup() {
    this.mockClients.forEach(client => client.disconnect());
    this.mockClients.clear();
    this.messageLog = [];
  }
}

// Jest Mock Setup Helpers
export const setupWebSocketMocks = () => {
  // Mock Socket.IO client
  jest.mock('socket.io-client', () => ({
    io: jest.fn(() => new MockSocketIOClient()),
  }));

  // Mock WebSocket browser API
  const mockWebSocket = class {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;

    readyState = 0;
    url = '';
    onopen: ((event: Event) => void) | null = null;
    onclose: ((event: CloseEvent) => void) | null = null;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: ((event: Event) => void) | null = null;

    constructor(url: string) {
      this.url = url;
      setTimeout(() => {
        this.readyState = 1;
        this.onopen?.(new Event('open'));
      }, 0);
    }

    send = jest.fn();
    close = jest.fn(() => {
      this.readyState = 3;
      this.onclose?.(new CloseEvent('close'));
    });
  };

  (global as any).WebSocket = mockWebSocket;

  return mockWebSocket;
};

// Test Data Generators
export const generateTerminalOutput = (lines: number = 10): string[] => {
  const outputs = [];
  for (let i = 1; i <= lines; i++) {
    outputs.push(`Line ${i}: Mock terminal output ${new Date().toISOString()}`);
  }
  return outputs;
};

export const generateLargeTerminalOutput = (sizeKB: number = 100): string => {
  const lineSize = 100; // ~100 chars per line
  const lines = Math.floor((sizeKB * 1024) / lineSize);
  return generateTerminalOutput(lines).join('\n');
};

// Connection State Machine Mock
export class MockConnectionStateMachine {
  private state: 'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'failed' = 'disconnected';
  private emitter = new EventEmitter();
  private retryCount = 0;
  private maxRetries = 3;

  connect() {
    if (this.state === 'connected' || this.state === 'connecting') return;
    
    this.state = 'connecting';
    this.emitter.emit('stateChange', this.state);
    
    setTimeout(() => {
      if (Math.random() < 0.9) { // 90% success rate
        this.state = 'connected';
        this.retryCount = 0;
      } else {
        this.state = 'failed';
        this.scheduleRetry();
      }
      this.emitter.emit('stateChange', this.state);
    }, 100);
  }

  disconnect() {
    this.state = 'disconnected';
    this.retryCount = 0;
    this.emitter.emit('stateChange', this.state);
  }

  private scheduleRetry() {
    if (this.retryCount < this.maxRetries) {
      this.retryCount++;
      this.state = 'reconnecting';
      this.emitter.emit('stateChange', this.state);
      
      setTimeout(() => {
        this.connect();
      }, 1000 * this.retryCount); // Exponential backoff
    }
  }

  on(event: 'stateChange', callback: (state: string) => void) {
    this.emitter.on(event, callback);
  }

  off(event: 'stateChange', callback: (state: string) => void) {
    this.emitter.off(event, callback);
  }

  getState() {
    return this.state;
  }

  getRetryCount() {
    return this.retryCount;
  }
}

export default {
  MockSocketIOClient,
  createMockWebSocketClient,
  createMockTerminalSession,
  WebSocketTestHarness,
  setupWebSocketMocks,
  generateTerminalOutput,
  generateLargeTerminalOutput,
  MockConnectionStateMachine,
  // Message builders
  createTerminalDataMessage,
  createTerminalResizeMessage,
  createTerminalConfigMessage,
  createSessionCreatedMessage,
  createSessionDestroyedMessage,
  createErrorMessage,
};