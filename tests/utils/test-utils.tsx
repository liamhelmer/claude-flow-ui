/**
 * Advanced Test Utilities for Claude Flow UI
 * Provides enhanced rendering, mocking, and assertion utilities
 */

import React from 'react';
import { render, RenderOptions, RenderResult } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { jest } from '@jest/globals';

// Types for enhanced test utilities
export interface TestState {
  agents: any[];
  prompts: any[];
  memory: any[];
  commands: any[];
  sessions: string[];
  activeSession: string;
  isCollapsed: boolean;
  error: string | null;
  loading: boolean;
}

export interface MockWebSocketConfig {
  url?: string;
  autoConnect?: boolean;
  simulateLatency?: number;
  failConnection?: boolean;
  customHandlers?: Record<string, (data: any) => void>;
}

export interface MockTerminalConfig {
  autoFocus?: boolean;
  simulateTyping?: boolean;
  preserveHistory?: boolean;
  customCommands?: Record<string, string>;
}

export interface RenderWithProvidersOptions extends RenderOptions {
  initialState?: Partial<TestState>;
  wsConfig?: MockWebSocketConfig;
  terminalConfig?: MockTerminalConfig;
  theme?: 'light' | 'dark';
  accessibility?: boolean;
}

// Factory functions for test data
export const createTabData = (overrides?: any) => ({
  id: 'test-tab-1',
  title: 'Test Terminal',
  content: 'Terminal content',
  isActive: false,
  closable: true,
  ...overrides,
});

export const createSessionData = (overrides?: any) => ({
  id: 'session-1',
  title: 'Test Session',
  command: 'bash',
  cwd: '/home/user',
  status: 'active',
  createdAt: new Date().toISOString(),
  ...overrides,
});

export const createAppState = (overrides?: Partial<TestState>): TestState => ({
  agents: [],
  prompts: [],
  memory: [],
  commands: [],
  sessions: ['session-1'],
  activeSession: 'session-1',
  isCollapsed: false,
  error: null,
  loading: false,
  ...overrides,
});

// Enhanced WebSocket Mock
export class MockWebSocket {
  private listeners: Record<string, Function[]> = {};
  private messageQueue: any[] = [];
  private isConnected = false;
  private config: MockWebSocketConfig;
  
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  
  readyState = MockWebSocket.CONNECTING;
  url: string;
  
  onopen?: (event: Event) => void;
  onclose?: (event: CloseEvent) => void;
  onmessage?: (event: MessageEvent) => void;
  onerror?: (event: Event) => void;

  constructor(url: string, config: MockWebSocketConfig = {}) {
    this.url = url;
    this.config = {
      autoConnect: true,
      simulateLatency: 10,
      failConnection: false,
      ...config,
    };
    
    if (this.config.autoConnect && !this.config.failConnection) {
      this.simulateConnection();
    } else if (this.config.failConnection) {
      this.simulateConnectionFailure();
    }
  }

  private simulateConnection() {
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.isConnected = true;
      this.onopen?.(new Event('open'));
      this.emit('open', new Event('open'));
    }, this.config.simulateLatency);
  }

  private simulateConnectionFailure() {
    setTimeout(() => {
      this.readyState = MockWebSocket.CLOSED;
      const error = new Event('error');
      this.onerror?.(error);
      this.emit('error', error);
    }, this.config.simulateLatency);
  }

  send(data: string | ArrayBuffer | Blob) {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error('WebSocket is not connected');
    }
    
    try {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data;
      this.messageQueue.push(parsed);
      
      // Handle custom message types
      if (this.config.customHandlers && parsed.type) {
        const handler = this.config.customHandlers[parsed.type];
        if (handler) {
          setTimeout(() => handler(parsed), this.config.simulateLatency);
        }
      }
    } catch (error) {
      console.warn('Failed to parse WebSocket message:', error);
    }
  }

  close(code?: number, reason?: string) {
    this.readyState = MockWebSocket.CLOSING;
    setTimeout(() => {
      this.readyState = MockWebSocket.CLOSED;
      this.isConnected = false;
      const closeEvent = new CloseEvent('close', { code, reason });
      this.onclose?.(closeEvent);
      this.emit('close', closeEvent);
    }, this.config.simulateLatency);
  }

  addEventListener(type: string, listener: Function) {
    if (!this.listeners[type]) {
      this.listeners[type] = [];
    }
    this.listeners[type].push(listener);
  }

  removeEventListener(type: string, listener: Function) {
    if (this.listeners[type]) {
      this.listeners[type] = this.listeners[type].filter(l => l !== listener);
    }
  }

  private emit(type: string, event: Event) {
    if (this.listeners[type]) {
      this.listeners[type].forEach(listener => listener(event));
    }
  }

  // Test helper methods
  simulateMessage(data: any) {
    if (this.readyState === MockWebSocket.OPEN) {
      const message = new MessageEvent('message', {
        data: typeof data === 'string' ? data : JSON.stringify(data),
      });
      this.onmessage?.(message);
      this.emit('message', message);
    }
  }

  simulateError(error: Error) {
    const errorEvent = new ErrorEvent('error', { error });
    this.onerror?.(errorEvent);
    this.emit('error', errorEvent);
  }

  simulateReconnect() {
    this.close();
    setTimeout(() => {
      this.readyState = MockWebSocket.CONNECTING;
      this.simulateConnection();
    }, 100);
  }

  getMessageQueue() {
    return [...this.messageQueue];
  }

  clearMessageQueue() {
    this.messageQueue = [];
  }
}

// Enhanced Terminal Mock
export class MockTerminal {
  private content: string[] = [];
  private cursor = { row: 0, col: 0 };
  private config: MockTerminalConfig;
  private eventListeners: Record<string, Function[]> = {};
  
  element?: HTMLElement;
  buffer = {
    active: {
      length: 0,
      getLine: (row: number) => ({
        translateToString: () => this.content[row] || '',
      }),
    },
  };

  constructor(config: MockTerminalConfig = {}) {
    this.config = {
      autoFocus: true,
      simulateTyping: false,
      preserveHistory: true,
      customCommands: {},
      ...config,
    };
  }

  write(data: string) {
    if (this.config.simulateTyping) {
      this.simulateTypingEffect(data);
    } else {
      this.content.push(data);
      this.buffer.active.length = this.content.length;
    }
    this.emit('data', data);
  }

  writeln(data: string) {
    this.write(data + '\r\n');
  }

  clear() {
    if (this.config.preserveHistory) {
      this.content = ['--- Terminal cleared ---'];
    } else {
      this.content = [];
    }
    this.cursor = { row: 0, col: 0 };
    this.buffer.active.length = this.content.length;
    this.emit('clear');
  }

  focus() {
    if (this.config.autoFocus && this.element) {
      this.element.focus();
    }
    this.emit('focus');
  }

  blur() {
    if (this.element) {
      this.element.blur();
    }
    this.emit('blur');
  }

  fit() {
    // Simulate terminal fitting
    this.emit('resize', { cols: 80, rows: 24 });
  }

  dispose() {
    this.content = [];
    this.eventListeners = {};
    this.emit('dispose');
  }

  scrollToBottom() {
    this.emit('scroll', { position: 'bottom' });
  }

  selectAll() {
    this.emit('selection', { type: 'all' });
  }

  on(event: string, callback: Function) {
    if (!this.eventListeners[event]) {
      this.eventListeners[event] = [];
    }
    this.eventListeners[event].push(callback);
  }

  off(event: string, callback: Function) {
    if (this.eventListeners[event]) {
      this.eventListeners[event] = this.eventListeners[event].filter(
        cb => cb !== callback
      );
    }
  }

  private emit(event: string, data?: any) {
    if (this.eventListeners[event]) {
      this.eventListeners[event].forEach(callback => callback(data));
    }
  }

  private simulateTypingEffect(data: string, delay = 50) {
    let index = 0;
    const type = () => {
      if (index < data.length) {
        this.content.push(data[index]);
        index++;
        setTimeout(type, delay);
      }
    };
    type();
  }

  // Test helper methods
  getContent() {
    return this.content.join('');
  }

  getLines() {
    return [...this.content];
  }

  simulateCommand(command: string) {
    this.write(`$ ${command}\r\n`);
    
    if (this.config.customCommands?.[command]) {
      setTimeout(() => {
        this.write(this.config.customCommands![command]);
      }, 100);
    } else {
      // Default command simulation
      setTimeout(() => {
        this.write(`Command output for: ${command}\r\n`);
      }, 100);
    }
  }

  simulateKeyPress(key: string, modifiers?: { ctrl?: boolean; shift?: boolean; alt?: boolean }) {
    const event = {
      key,
      ctrlKey: modifiers?.ctrl || false,
      shiftKey: modifiers?.shift || false,
      altKey: modifiers?.alt || false,
    };
    this.emit('keydown', event);
  }
}

// Enhanced App Store Mock
export const createMockStore = (initialState?: Partial<TestState>) => {
  const state = createAppState(initialState);
  
  return {
    // State getters
    ...state,
    
    // Actions
    setError: jest.fn((error: string | null) => {
      state.error = error;
    }),
    setLoading: jest.fn((loading: boolean) => {
      state.loading = loading;
    }),
    toggleSidebar: jest.fn(() => {
      state.isCollapsed = !state.isCollapsed;
    }),
    addAgent: jest.fn((agent: any) => {
      state.agents.push(agent);
    }),
    removeAgent: jest.fn((agentId: string) => {
      state.agents = state.agents.filter(a => a.id !== agentId);
    }),
    addSession: jest.fn((session: string) => {
      state.sessions.push(session);
    }),
    removeSession: jest.fn((sessionId: string) => {
      state.sessions = state.sessions.filter(s => s !== sessionId);
    }),
    setActiveSession: jest.fn((sessionId: string) => {
      state.activeSession = sessionId;
    }),
    
    // Test helpers
    getState: () => ({ ...state }),
    resetState: () => {
      Object.assign(state, createAppState(initialState));
    },
  };
};

// Global mock setup
export const setupGlobalMocks = () => {
  // WebSocket global mock
  (global as any).WebSocket = MockWebSocket;
  
  // Terminal mock for xterm
  jest.mock('@xterm/xterm', () => ({
    Terminal: MockTerminal,
  }));
  
  // Socket.io mock
  jest.mock('socket.io-client', () => ({
    io: jest.fn(() => ({
      connect: jest.fn(),
      disconnect: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      emit: jest.fn(),
      connected: true,
    })),
  }));

  // Resize Observer mock
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  })) as any;

  // Intersection Observer mock
  global.IntersectionObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  })) as any;
};

// Enhanced render function with providers
export const renderWithProviders = (
  ui: React.ReactElement,
  options: RenderWithProvidersOptions = {}
): RenderResult & {
  user: ReturnType<typeof userEvent.setup>;
  mockStore: ReturnType<typeof createMockStore>;
  mockWs: MockWebSocket;
} => {
  const {
    initialState,
    wsConfig,
    terminalConfig,
    theme = 'dark',
    accessibility = true,
    ...renderOptions
  } = options;

  // Setup mocks
  const mockStore = createMockStore(initialState);
  const mockWs = new MockWebSocket('ws://localhost:11237', wsConfig);
  
  // Mock providers
  const MockStoreProvider = ({ children }: { children: React.ReactNode }) => {
    // Mock the store context
    React.useEffect(() => {
      // Simulate store initialization
    }, []);
    
    return <>{children}</>;
  };

  const MockWebSocketProvider = ({ children }: { children: React.ReactNode }) => {
    return <>{children}</>;
  };

  const AllProviders = ({ children }: { children: React.ReactNode }) => (
    <MockStoreProvider>
      <MockWebSocketProvider>
        <div data-theme={theme} data-testid="test-wrapper">
          {children}
        </div>
      </MockWebSocketProvider>
    </MockStoreProvider>
  );

  const user = userEvent.setup({
    advanceTimers: jest.advanceTimersByTime,
  });

  const result = render(ui, {
    wrapper: AllProviders,
    ...renderOptions,
  });

  return {
    ...result,
    user,
    mockStore,
    mockWs,
  };
};

// Performance testing utilities
export const measureRenderTime = (renderFn: () => void): number => {
  const start = performance.now();
  renderFn();
  const end = performance.now();
  return end - start;
};

export const measureMemoryUsage = (operation: () => void): number => {
  const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;
  operation();
  // Force garbage collection if available
  if ((global as any).gc) {
    (global as any).gc();
  }
  const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
  return finalMemory - initialMemory;
};

// Accessibility testing helpers
export const checkAccessibility = async (container: HTMLElement, rules?: any) => {
  const { axe } = await import('jest-axe');
  return axe(container, {
    rules: {
      'color-contrast': { enabled: true },
      'focus-order-semantics': { enabled: true },
      'keyboard-navigation': { enabled: true },
      ...rules,
    },
  });
};

// Async testing utilities
export const waitForWebSocket = async (
  mockWs: MockWebSocket,
  state: 'open' | 'closed' | 'error',
  timeout = 5000
): Promise<void> => {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`WebSocket did not reach ${state} state within ${timeout}ms`));
    }, timeout);

    const checkState = () => {
      if (
        (state === 'open' && mockWs.readyState === MockWebSocket.OPEN) ||
        (state === 'closed' && mockWs.readyState === MockWebSocket.CLOSED) ||
        (state === 'error' && mockWs.readyState === MockWebSocket.CLOSED)
      ) {
        clearTimeout(timer);
        resolve();
      } else {
        setTimeout(checkState, 10);
      }
    };

    checkState();
  });
};

// Error boundary testing
export const TestErrorBoundary = ({ children, onError }: {
  children: React.ReactNode;
  onError?: (error: Error) => void;
}) => {
  const [hasError, setHasError] = React.useState(false);
  const [error, setError] = React.useState<Error | null>(null);

  React.useEffect(() => {
    if (error && onError) {
      onError(error);
    }
  }, [error, onError]);

  if (hasError) {
    return <div data-testid="error-boundary">Something went wrong</div>;
  }

  const errorHandler = (error: Error, errorInfo: any) => {
    setHasError(true);
    setError(error);
  };

  return (
    <React.Component
      children={children}
      componentDidCatch={errorHandler}
    />
  );
};

// Export all utilities
export * from '@testing-library/react';
export { userEvent };