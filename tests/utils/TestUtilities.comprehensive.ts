/**
 * Comprehensive Test Utilities for Claude Flow UI
 * Provides reusable mocks, helpers, and patterns for testing
 */

import React from 'react';
import { render, RenderOptions, RenderResult } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { TerminalSession, WebSocketMessage } from '@/types';

// ============================================================================
// MOCK FACTORIES
// ============================================================================

export const createMockTerminalSession = (overrides: Partial<TerminalSession> = {}): TerminalSession => ({
  id: `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  name: 'Test Terminal',
  isActive: true,
  lastActivity: new Date(),
  ...overrides,
});

export const createMockWebSocketMessage = (overrides: Partial<WebSocketMessage> = {}): WebSocketMessage => ({
  type: 'data',
  sessionId: 'test-session',
  data: 'test output',
  ...overrides,
});

export const createMockTerminalConfig = (overrides: Partial<any> = {}) => ({
  cols: 80,
  rows: 24,
  fontSize: 14,
  fontFamily: 'JetBrains Mono, monospace',
  theme: 'dark',
  cursorBlink: true,
  scrollback: 10000,
  ...overrides,
});

export const createMockPerformanceMetrics = (overrides: Partial<any> = {}) => ({
  renderTime: 16.7,
  memoryUsage: 10000000,
  componentCount: 150,
  reRenderCount: 1,
  updateTime: Date.now(),
  cpuUsage: 25.5,
  networkLatency: 45,
  ...overrides,
});

// ============================================================================
// MOCK PROVIDERS
// ============================================================================

export class MockWebSocketClient {
  connected = false;
  connecting = false;
  private listeners = new Map<string, Function[]>();

  connect = jest.fn().mockResolvedValue(undefined);
  disconnect = jest.fn();
  send = jest.fn();
  sendMessage = jest.fn();

  on = jest.fn((event: string, callback: Function) => {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  });

  off = jest.fn((event: string, callback: Function) => {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      const index = eventListeners.indexOf(callback);
      if (index > -1) {
        eventListeners.splice(index, 1);
      }
    }
  });

  emit(event: string, data: any) {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.forEach(callback => callback(data));
    }
  }

  reset() {
    this.connected = false;
    this.connecting = false;
    this.listeners.clear();
    jest.clearAllMocks();
  }
}

export class MockTerminal {
  cols = 80;
  rows = 24;
  element = document.createElement('div');

  open = jest.fn();
  write = jest.fn();
  writeln = jest.fn();
  clear = jest.fn();
  focus = jest.fn();
  blur = jest.fn();
  dispose = jest.fn();
  onData = jest.fn();
  onResize = jest.fn();
  onKey = jest.fn();
  onTitleChange = jest.fn();
  loadAddon = jest.fn();
  scrollToBottom = jest.fn();
  scrollToTop = jest.fn();

  private dataCallback: ((data: string) => void) | null = null;

  constructor() {
    this.onData.mockImplementation((callback: (data: string) => void) => {
      this.dataCallback = callback;
    });
  }

  simulateInput(data: string) {
    if (this.dataCallback) {
      this.dataCallback(data);
    }
  }

  reset() {
    this.dataCallback = null;
    jest.clearAllMocks();
  }
}

export class MockAppStore {
  terminalSessions: TerminalSession[] = [];
  activeSessionId: string | null = null;
  sidebarOpen = true;
  loading = false;
  error: string | null = null;

  // Actions
  createNewSession = jest.fn().mockImplementation(() => {
    const sessionId = `session-${Date.now()}`;
    const session = createMockTerminalSession({ id: sessionId });
    this.terminalSessions.push(session);
    this.activeSessionId = sessionId;
    return sessionId;
  });

  setActiveSession = jest.fn().mockImplementation((sessionId: string) => {
    this.activeSessionId = sessionId;
  });

  removeSession = jest.fn().mockImplementation((sessionId: string) => {
    this.terminalSessions = this.terminalSessions.filter(s => s.id !== sessionId);
    if (this.activeSessionId === sessionId) {
      this.activeSessionId = this.terminalSessions[0]?.id || null;
    }
  });

  addSession = jest.fn().mockImplementation((session: TerminalSession) => {
    this.terminalSessions.push(session);
  });

  updateSession = jest.fn().mockImplementation((sessionId: string, updates: Partial<TerminalSession>) => {
    const sessionIndex = this.terminalSessions.findIndex(s => s.id === sessionId);
    if (sessionIndex > -1) {
      this.terminalSessions[sessionIndex] = { ...this.terminalSessions[sessionIndex], ...updates };
    }
  });

  clearSessions = jest.fn().mockImplementation(() => {
    this.terminalSessions = [];
    this.activeSessionId = null;
  });

  setSidebarOpen = jest.fn().mockImplementation((open: boolean) => {
    this.sidebarOpen = open;
  });

  toggleSidebar = jest.fn().mockImplementation(() => {
    this.sidebarOpen = !this.sidebarOpen;
  });

  setLoading = jest.fn().mockImplementation((loading: boolean) => {
    this.loading = loading;
  });

  setError = jest.fn().mockImplementation((error: string | null) => {
    this.error = error;
  });

  reset() {
    this.terminalSessions = [];
    this.activeSessionId = null;
    this.sidebarOpen = true;
    this.loading = false;
    this.error = null;
    jest.clearAllMocks();
  }
}

// ============================================================================
// TEST HELPERS
// ============================================================================

export const waitForTime = (ms: number): Promise<void> => 
  new Promise(resolve => setTimeout(resolve, ms));

export const flushPromises = (): Promise<void> => 
  new Promise(resolve => setImmediate(resolve));

export const advanceTimersAndFlush = async (ms: number): Promise<void> => {
  jest.advanceTimersByTime(ms);
  await flushPromises();
};

export const createMockObserver = () => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
});

export const mockResizeObserver = () => {
  global.ResizeObserver = jest.fn().mockImplementation(() => createMockObserver());
};

export const mockIntersectionObserver = () => {
  global.IntersectionObserver = jest.fn().mockImplementation(() => createMockObserver());
};

export const mockMatchMedia = () => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: jest.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    })),
  });
};

export const mockLocalStorage = () => {
  const store: Record<string, string> = {};
  
  Object.defineProperty(window, 'localStorage', {
    value: {
      getItem: jest.fn((key: string) => store[key] || null),
      setItem: jest.fn((key: string, value: string) => {
        store[key] = value;
      }),
      removeItem: jest.fn((key: string) => {
        delete store[key];
      }),
      clear: jest.fn(() => {
        Object.keys(store).forEach(key => delete store[key]);
      }),
      length: Object.keys(store).length,
      key: jest.fn((index: number) => Object.keys(store)[index] || null),
    },
    writable: true,
  });
  
  return store;
};

export const mockSessionStorage = () => {
  const store: Record<string, string> = {};
  
  Object.defineProperty(window, 'sessionStorage', {
    value: {
      getItem: jest.fn((key: string) => store[key] || null),
      setItem: jest.fn((key: string, value: string) => {
        store[key] = value;
      }),
      removeItem: jest.fn((key: string) => {
        delete store[key];
      }),
      clear: jest.fn(() => {
        Object.keys(store).forEach(key => delete store[key]);
      }),
      length: Object.keys(store).length,
      key: jest.fn((index: number) => Object.keys(store)[index] || null),
    },
    writable: true,
  });
  
  return store;
};

export const mockPerformanceAPI = () => {
  const mockMemory = {
    usedJSHeapSize: 10000000,
    totalJSHeapSize: 20000000,
    jsHeapSizeLimit: 50000000,
  };

  Object.defineProperty(performance, 'memory', {
    value: mockMemory,
    configurable: true,
  });

  const originalNow = performance.now;
  jest.spyOn(performance, 'now').mockImplementation(() => Date.now());

  return {
    memory: mockMemory,
    restoreNow: () => {
      performance.now = originalNow;
    },
  };
};

// ============================================================================
// RENDERING UTILITIES
// ============================================================================

interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialStore?: Partial<MockAppStore>;
  mockWebSocket?: Partial<MockWebSocketClient>;
  mockTerminal?: Partial<MockTerminal>;
}

export const renderWithMocks = (
  ui: React.ReactElement,
  options: CustomRenderOptions = {}
): RenderResult & {
  mockStore: MockAppStore;
  mockWebSocket: MockWebSocketClient;
  mockTerminal: MockTerminal;
  user: ReturnType<typeof userEvent.setup>;
} => {
  const mockStore = new MockAppStore();
  const mockWebSocket = new MockWebSocketClient();
  const mockTerminal = new MockTerminal();

  // Apply overrides
  if (options.initialStore) {
    Object.assign(mockStore, options.initialStore);
  }
  if (options.mockWebSocket) {
    Object.assign(mockWebSocket, options.mockWebSocket);
  }
  if (options.mockTerminal) {
    Object.assign(mockTerminal, options.mockTerminal);
  }

  const user = userEvent.setup({ delay: null });

  const renderResult = render(ui, options);

  return {
    ...renderResult,
    mockStore,
    mockWebSocket,
    mockTerminal,
    user,
  };
};

// ============================================================================
// ASSERTION HELPERS
// ============================================================================

export const expectElementToHaveClasses = (element: HTMLElement, classes: string[]) => {
  classes.forEach(className => {
    expect(element).toHaveClass(className);
  });
};

export const expectElementNotToHaveClasses = (element: HTMLElement, classes: string[]) => {
  classes.forEach(className => {
    expect(element).not.toHaveClass(className);
  });
};

export const expectToBeAccessible = (element: HTMLElement) => {
  // Basic accessibility checks
  if (element.tagName === 'BUTTON') {
    expect(element).toHaveAttribute('type');
  }
  
  if (element.hasAttribute('aria-label') || element.hasAttribute('aria-labelledby')) {
    expect(element).toBeInTheDocument();
  }
  
  if (element.getAttribute('role') === 'button') {
    expect(element).toHaveAttribute('tabindex');
  }
};

export const expectPerformanceMetrics = (metrics: any) => {
  expect(metrics).toHaveProperty('renderTime');
  expect(metrics).toHaveProperty('memoryUsage');
  expect(metrics).toHaveProperty('componentCount');
  expect(typeof metrics.renderTime).toBe('number');
  expect(typeof metrics.memoryUsage).toBe('number');
  expect(typeof metrics.componentCount).toBe('number');
};

// ============================================================================
// TEST DATA GENERATORS
// ============================================================================

export const generateSessionData = (count: number): TerminalSession[] => 
  Array.from({ length: count }, (_, i) => createMockTerminalSession({
    id: `session-${i}`,
    name: `Terminal ${i + 1}`,
    isActive: i === 0,
  }));

export const generateWebSocketMessages = (count: number): WebSocketMessage[] =>
  Array.from({ length: count }, (_, i) => createMockWebSocketMessage({
    type: 'data',
    sessionId: `session-${i % 3}`,
    data: `Message ${i}: ${Math.random().toString(36)}`,
  }));

export const generateLargeTerminalOutput = (lines: number): string =>
  Array.from({ length: lines }, (_, i) => `Line ${i}: ${Math.random().toString(36)}`).join('\n');

// ============================================================================
// STRESS TESTING UTILITIES
// ============================================================================

export const stressTestComponent = async (
  renderFn: () => RenderResult,
  iterations: number = 100
): Promise<{ averageRenderTime: number; maxRenderTime: number; errors: Error[] }> => {
  const renderTimes: number[] = [];
  const errors: Error[] = [];

  for (let i = 0; i < iterations; i++) {
    try {
      const startTime = performance.now();
      const result = renderFn();
      const endTime = performance.now();
      
      renderTimes.push(endTime - startTime);
      result.unmount();
    } catch (error) {
      errors.push(error as Error);
    }
  }

  return {
    averageRenderTime: renderTimes.reduce((a, b) => a + b, 0) / renderTimes.length,
    maxRenderTime: Math.max(...renderTimes),
    errors,
  };
};

export const measureMemoryUsage = (): number => {
  if ('memory' in performance && (performance as any).memory) {
    return (performance as any).memory.usedJSHeapSize;
  }
  return 0;
};

export const detectMemoryLeaks = async (
  testFn: () => Promise<void> | void,
  iterations: number = 10
): Promise<{ leaked: boolean; memoryIncrease: number }> => {
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }

  const initialMemory = measureMemoryUsage();

  for (let i = 0; i < iterations; i++) {
    await testFn();
  }

  // Force garbage collection again
  if (global.gc) {
    global.gc();
  }

  const finalMemory = measureMemoryUsage();
  const memoryIncrease = finalMemory - initialMemory;

  return {
    leaked: memoryIncrease > 1000000, // 1MB threshold
    memoryIncrease,
  };
};

// ============================================================================
// ERROR SIMULATION UTILITIES
// ============================================================================

export const simulateNetworkError = () => {
  const originalFetch = global.fetch;
  global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));
  return () => {
    global.fetch = originalFetch;
  };
};

export const simulateWebSocketError = (mockClient: MockWebSocketClient, error: Error) => {
  mockClient.emit('error', error);
};

export const simulateTerminalError = (mockTerminal: MockTerminal, error: string) => {
  mockTerminal.write.mockImplementation(() => {
    throw new Error(error);
  });
};

// ============================================================================
// CLEANUP UTILITIES
// ============================================================================

export const cleanupMocks = (
  mockStore?: MockAppStore,
  mockWebSocket?: MockWebSocketClient,
  mockTerminal?: MockTerminal
) => {
  mockStore?.reset();
  mockWebSocket?.reset();
  mockTerminal?.reset();
  jest.clearAllMocks();
};

export const cleanupTimers = () => {
  jest.clearAllTimers();
  jest.useRealTimers();
};

export const cleanupGlobals = () => {
  // Restore console methods
  if (jest.isMockFunction(console.log)) {
    (console.log as jest.MockedFunction<typeof console.log>).mockRestore();
  }
  if (jest.isMockFunction(console.error)) {
    (console.error as jest.MockedFunction<typeof console.error>).mockRestore();
  }
  if (jest.isMockFunction(console.warn)) {
    (console.warn as jest.MockedFunction<typeof console.warn>).mockRestore();
  }
};

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Factories
  createMockTerminalSession,
  createMockWebSocketMessage,
  createMockTerminalConfig,
  createMockPerformanceMetrics,
  
  // Mock providers
  MockWebSocketClient,
  MockTerminal,
  MockAppStore,
  
  // Helpers
  waitForTime,
  flushPromises,
  advanceTimersAndFlush,
  
  // Mocking utilities
  mockResizeObserver,
  mockIntersectionObserver,
  mockMatchMedia,
  mockLocalStorage,
  mockSessionStorage,
  mockPerformanceAPI,
  
  // Rendering
  renderWithMocks,
  
  // Assertions
  expectElementToHaveClasses,
  expectElementNotToHaveClasses,
  expectToBeAccessible,
  expectPerformanceMetrics,
  
  // Data generation
  generateSessionData,
  generateWebSocketMessages,
  generateLargeTerminalOutput,
  
  // Stress testing
  stressTestComponent,
  measureMemoryUsage,
  detectMemoryLeaks,
  
  // Error simulation
  simulateNetworkError,
  simulateWebSocketError,
  simulateTerminalError,
  
  // Cleanup
  cleanupMocks,
  cleanupTimers,
  cleanupGlobals,
};