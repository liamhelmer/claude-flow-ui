/**
 * Enhanced Test Utilities for Claude Flow UI
 * Provides comprehensive testing helpers, factories, and custom matchers
 */

import { render, RenderOptions, RenderResult } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { performance } from 'perf_hooks';
import { ReactElement, ReactNode } from 'react';

// ============================================================================
// PERFORMANCE TESTING UTILITIES
// ============================================================================

export class PerformanceBenchmark {
  private marks: Map<string, number> = new Map();
  private measures: Map<string, number> = new Map();

  mark(name: string): void {
    this.marks.set(name, performance.now());
  }

  measure(name: string, startMark: string, endMark?: string): number {
    const start = this.marks.get(startMark);
    const end = endMark ? this.marks.get(endMark) : performance.now();

    if (!start || (endMark && !end)) {
      throw new Error(`Mark not found: ${startMark} or ${endMark}`);
    }

    const duration = (end as number) - start;
    this.measures.set(name, duration);
    return duration;
  }

  getMeasure(name: string): number | undefined {
    return this.measures.get(name);
  }

  getAll(): Record<string, number> {
    return Object.fromEntries(this.measures);
  }

  clear(): void {
    this.marks.clear();
    this.measures.clear();
  }

  async measureAsync<T>(name: string, fn: () => Promise<T>): Promise<T> {
    this.mark(`${name}_start`);
    const result = await fn();
    this.measure(name, `${name}_start`);
    return result;
  }

  measureSync<T>(name: string, fn: () => T): T {
    this.mark(`${name}_start`);
    const result = fn();
    this.measure(name, `${name}_start`);
    return result;
  }
}

// ============================================================================
// MEMORY TESTING UTILITIES
// ============================================================================

export class MemoryMonitor {
  private baseline: number = 0;
  private samples: number[] = [];

  setBaseline(): void {
    this.baseline = this.getCurrentMemoryUsage();
  }

  getCurrentMemoryUsage(): number {
    if (typeof window !== 'undefined' && 'performance' in window && 'memory' in window.performance) {
      return (window.performance as any).memory.usedJSHeapSize;
    }
    // Fallback for Node.js environment
    return process.memoryUsage().heapUsed;
  }

  sample(): void {
    this.samples.push(this.getCurrentMemoryUsage());
  }

  getMemoryIncrease(): number {
    return this.getCurrentMemoryUsage() - this.baseline;
  }

  getAverageUsage(): number {
    if (this.samples.length === 0) return 0;
    return this.samples.reduce((sum, sample) => sum + sample, 0) / this.samples.length;
  }

  getPeakUsage(): number {
    return Math.max(...this.samples);
  }

  checkForLeaks(threshold: number = 50 * 1024 * 1024): boolean {
    return this.getMemoryIncrease() > threshold;
  }

  reset(): void {
    this.baseline = 0;
    this.samples = [];
  }
}

// ============================================================================
// MOCK FACTORIES
// ============================================================================

export interface MockWebSocketConfig {
  readyState?: number;
  url?: string;
  protocol?: string;
  binaryType?: string;
}

export class TestMockFactory {
  static createWebSocketMock(config: MockWebSocketConfig = {}): jest.MockedClass<typeof WebSocket> {
    const mockWebSocket = jest.fn().mockImplementation(() => ({
      readyState: config.readyState ?? WebSocket.OPEN,
      url: config.url ?? 'ws://localhost:8080',
      protocol: config.protocol ?? '',
      binaryType: config.binaryType ?? 'blob',
      send: jest.fn(),
      close: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
      onopen: null,
      onclose: null,
      onmessage: null,
      onerror: null,
    }));

    // Add the static constants to match WebSocket class
    Object.defineProperty(mockWebSocket, 'CONNECTING', { value: 0, writable: false });
    Object.defineProperty(mockWebSocket, 'OPEN', { value: 1, writable: false });
    Object.defineProperty(mockWebSocket, 'CLOSING', { value: 2, writable: false });
    Object.defineProperty(mockWebSocket, 'CLOSED', { value: 3, writable: false });

    return mockWebSocket as unknown as jest.MockedClass<typeof WebSocket>;
  }

  static createTerminalMock() {
    return {
      dispose: jest.fn(),
      write: jest.fn(),
      writeln: jest.fn(),
      clear: jest.fn(),
      reset: jest.fn(),
      resize: jest.fn(),
      focus: jest.fn(),
      blur: jest.fn(),
      getSelection: jest.fn().mockReturnValue(''),
      clearSelection: jest.fn(),
      selectAll: jest.fn(),
      onData: jest.fn(),
      onRender: jest.fn(),
      onResize: jest.fn(),
      onSelectionChange: jest.fn(),
      loadAddon: jest.fn(),
      element: document.createElement('div'),
      cols: 80,
      rows: 24,
      markers: [],
      modes: {},
      options: {},
      buffer: {
        active: {
          baseY: 0,
          cursorX: 0,
          cursorY: 0,
          viewportY: 0,
          length: 24,
          getLine: jest.fn().mockReturnValue({ translateToString: jest.fn().mockReturnValue('') }),
        },
        normal: {
          baseY: 0,
          cursorX: 0,
          cursorY: 0,
          viewportY: 0,
          length: 24,
          getLine: jest.fn().mockReturnValue({ translateToString: jest.fn().mockReturnValue('') }),
        },
      },
    };
  }

  static createUserSessionMock(sessionId: string = 'test-session') {
    return {
      id: sessionId,
      title: `Session ${sessionId}`,
      isActive: true,
      createdAt: new Date(),
      lastActivity: new Date(),
      command: 'bash',
      workingDirectory: '/home/user',
      status: 'active' as const,
      pid: 12345,
      pty: null,
    };
  }

  static createWebSocketMessageMock(type: string, data: any = {}) {
    return {
      type,
      sessionId: 'test-session',
      timestamp: Date.now(),
      data,
    };
  }

  static createPerformanceEntryMock(name: string, duration: number = 10) {
    return {
      name,
      entryType: 'measure',
      startTime: performance.now() - duration,
      duration,
      detail: null,
    };
  }
}

// ============================================================================
// ENHANCED RENDER UTILITIES
// ============================================================================

interface EnhancedRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  withPerformanceMonitoring?: boolean;
  withMemoryMonitoring?: boolean;
  withUserEvents?: boolean;
  performanceThreshold?: number;
  memoryThreshold?: number;
}

interface EnhancedRenderResult extends RenderResult {
  user?: ReturnType<typeof userEvent.setup>;
  performance?: PerformanceBenchmark;
  memory?: MemoryMonitor;
  cleanup: () => void;
}

export function renderWithEnhancements(
  ui: ReactElement,
  options: EnhancedRenderOptions = {}
): EnhancedRenderResult {
  const {
    withPerformanceMonitoring = false,
    withMemoryMonitoring = false,
    withUserEvents = true,
    performanceThreshold = 100,
    memoryThreshold = 50 * 1024 * 1024,
    ...renderOptions
  } = options;

  // Initialize monitoring tools
  const performance = withPerformanceMonitoring ? new PerformanceBenchmark() : undefined;
  const memory = withMemoryMonitoring ? new MemoryMonitor() : undefined;
  const user = withUserEvents ? userEvent.setup() : undefined;

  // Set baselines
  if (memory) {
    memory.setBaseline();
  }

  if (performance) {
    performance.mark('render_start');
  }

  // Render component
  const result = render(ui, renderOptions);

  if (performance) {
    performance.measure('render_duration', 'render_start');

    // Check performance threshold
    const renderDuration = performance.getMeasure('render_duration');
    if (renderDuration && renderDuration > performanceThreshold) {
      console.warn(`Render took ${renderDuration}ms, exceeding threshold of ${performanceThreshold}ms`);
    }
  }

  if (memory) {
    memory.sample();
  }

  // Enhanced cleanup function
  const cleanup = () => {
    if (memory) {
      const increase = memory.getMemoryIncrease();
      if (increase > memoryThreshold) {
        console.warn(`Memory increased by ${increase} bytes, exceeding threshold of ${memoryThreshold} bytes`);
      }
      memory.reset();
    }

    if (performance) {
      performance.clear();
    }

    result.unmount();
  };

  return {
    ...result,
    user,
    performance,
    memory,
    cleanup,
  };
}

// ============================================================================
// TESTING HELPERS
// ============================================================================

export async function waitForCondition(
  condition: () => boolean | Promise<boolean>,
  timeout: number = 5000,
  interval: number = 50
): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }

  throw new Error(`Condition not met within ${timeout}ms timeout`);
}

export function createMockPromise<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: any) => void;
} {
  let resolve: (value: T) => void;
  let reject: (reason?: any) => void;

  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve: resolve!, reject: reject! };
}

export async function simulateDelay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function generateRandomString(length: number = 10): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export function generateLargeText(sizeInKB: number): string {
  const baseText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ';
  const targetSize = sizeInKB * 1024;
  let result = '';

  while (result.length < targetSize) {
    result += baseText;
  }

  return result.substring(0, targetSize);
}

// ============================================================================
// CUSTOM JEST MATCHERS
// ============================================================================

declare global {
  namespace jest {
    interface Matchers<R> {
      toBeWithinPerformanceBudget(threshold: number): R;
      toHaveMemoryLeakBelow(threshold: number): R;
      toCompleteWithinTimeout(timeout: number): R;
      toHaveValidWebSocketConnection(): R;
      toRenderWithoutErrors(): R;
    }
  }
}

// Performance budget matcher
expect.extend({
  toBeWithinPerformanceBudget(received: number, threshold: number) {
    const pass = received <= threshold;
    return {
      message: () =>
        pass
          ? `Expected ${received}ms to exceed performance budget of ${threshold}ms`
          : `Expected ${received}ms to be within performance budget of ${threshold}ms`,
      pass,
    };
  },

  toHaveMemoryLeakBelow(received: number, threshold: number) {
    const pass = received < threshold;
    return {
      message: () =>
        pass
          ? `Expected memory usage ${received} bytes to exceed threshold of ${threshold} bytes`
          : `Expected memory usage ${received} bytes to be below threshold of ${threshold} bytes`,
      pass,
    };
  },

  async toCompleteWithinTimeout(received: Promise<any>, timeout: number) {
    try {
      const start = performance.now();
      await received;
      const duration = performance.now() - start;
      const pass = duration <= timeout;

      return {
        message: () =>
          pass
            ? `Expected operation to take longer than ${timeout}ms but completed in ${duration}ms`
            : `Expected operation to complete within ${timeout}ms but took ${duration}ms`,
        pass,
      };
    } catch (error) {
      return {
        message: () => `Operation failed: ${error}`,
        pass: false,
      };
    }
  },

  toHaveValidWebSocketConnection(received: any) {
    const hasRequiredMethods =
      typeof received?.send === 'function' &&
      typeof received?.close === 'function' &&
      typeof received?.addEventListener === 'function';

    const hasValidReadyState =
      typeof received?.readyState === 'number' &&
      received.readyState >= 0 &&
      received.readyState <= 3;

    const pass = hasRequiredMethods && hasValidReadyState;

    return {
      message: () =>
        pass
          ? `Expected WebSocket to be invalid`
          : `Expected WebSocket to have valid methods and ready state`,
      pass,
    };
  },

  toRenderWithoutErrors(received: () => any) {
    try {
      received();
      return {
        message: () => `Expected render function to throw an error`,
        pass: true,
      };
    } catch (error) {
      return {
        message: () => `Expected render function not to throw, but got: ${error}`,
        pass: false,
      };
    }
  },
});

// ============================================================================
// TEST DATA GENERATORS
// ============================================================================

export class TestDataGenerator {
  static createTerminalSession(overrides: Partial<any> = {}) {
    return {
      id: generateRandomString(8),
      title: `Terminal ${Math.floor(Math.random() * 1000)}`,
      command: 'bash',
      workingDirectory: '/home/user',
      status: 'active',
      createdAt: new Date(),
      lastActivity: new Date(),
      ...overrides,
    };
  }

  static createWebSocketMessage(type: string, data: any = {}) {
    return {
      id: generateRandomString(16),
      type,
      sessionId: generateRandomString(8),
      timestamp: Date.now(),
      data,
    };
  }

  static createPerformanceMetrics(overrides: Partial<any> = {}) {
    return {
      renderTime: Math.floor(Math.random() * 50) + 10,
      memoryUsage: Math.floor(Math.random() * 1000000) + 500000,
      messagesSent: Math.floor(Math.random() * 100),
      messagesReceived: Math.floor(Math.random() * 100),
      connectionTime: Math.floor(Math.random() * 1000) + 100,
      ...overrides,
    };
  }

  static createMaliciousInputs() {
    return {
      xss: [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '<img src="x" onerror="alert(\'XSS\')">',
        '<svg onload=alert(1)>',
        '"><svg/onload=alert(/XSS/)>',
      ],
      injection: [
        '\'; DROP TABLE sessions; --',
        '1\' OR \'1\'=\'1',
        'admin\'--',
        '\' UNION SELECT password FROM users--',
      ],
      pathTraversal: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/shadow',
        '....//....//....//etc//passwd',
      ],
      oversized: [
        'A'.repeat(10000),
        'A'.repeat(100000),
      ],
    };
  }
}

// Export all utilities as default
export default {
  PerformanceBenchmark,
  MemoryMonitor,
  TestMockFactory,
  renderWithEnhancements,
  waitForCondition,
  createMockPromise,
  simulateDelay,
  generateRandomString,
  generateLargeText,
  TestDataGenerator,
};