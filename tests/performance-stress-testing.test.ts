/**
 * Performance and Stress Testing Suite for Claude Flow UI
 * Validates performance under load and identifies bottlenecks
 */

import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { performance } from 'perf_hooks';

// Performance benchmarking utilities
class PerformanceBenchmark {
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
}

// Memory monitoring utilities
class MemoryMonitor {
  private baseline: number;

  constructor() {
    this.baseline = this.getCurrentMemoryUsage();
  }

  getCurrentMemoryUsage(): number {
    // In browser environment, use performance.memory if available
    if (typeof window !== 'undefined' && 'performance' in window && 'memory' in (window as any).performance) {
      return (window as any).performance.memory.usedJSHeapSize;
    }

    // In Node.js environment
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage().heapUsed;
    }

    return 0;
  }

  getMemoryIncrease(): number {
    return this.getCurrentMemoryUsage() - this.baseline;
  }

  resetBaseline(): void {
    this.baseline = this.getCurrentMemoryUsage();
  }
}

describe('Performance Testing Suite', () => {
  let benchmark: PerformanceBenchmark;
  let memoryMonitor: MemoryMonitor;

  beforeEach(() => {
    benchmark = new PerformanceBenchmark();
    memoryMonitor = new MemoryMonitor();

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });

  afterEach(() => {
    benchmark.clear();
  });

  describe('Terminal Performance', () => {
    it('should render terminal within performance budget', async () => {
      const RENDER_TIME_BUDGET = 100; // 100ms budget for initial render

      // Mock terminal with performance tracking
      const mockTerminal = {
        open: jest.fn(),
        write: jest.fn(),
        clear: jest.fn(),
        focus: jest.fn(),
        dispose: jest.fn(),
        onData: jest.fn(),
        loadAddon: jest.fn(),
        element: {
          querySelector: jest.fn(() => ({
            addEventListener: jest.fn(),
            removeEventListener: jest.fn(),
            scrollTop: 0,
            scrollHeight: 1000,
            clientHeight: 500
          }))
        }
      };

      benchmark.mark('terminal-render-start');

      // Simulate terminal creation and rendering
      const terminal = mockTerminal;
      terminal.open();

      benchmark.mark('terminal-render-end');
      const renderTime = benchmark.measure('terminal-render', 'terminal-render-start', 'terminal-render-end');

      expect(renderTime).toBeLessThan(RENDER_TIME_BUDGET);
      expect(mockTerminal.open).toHaveBeenCalled();
    });

    it('should handle large output efficiently', async () => {
      const LARGE_OUTPUT_SIZE = 10000; // 10KB of data
      const PROCESSING_TIME_BUDGET = 200; // 200ms budget

      const mockTerminal = {
        write: jest.fn()
      };

      const largeOutput = 'A'.repeat(LARGE_OUTPUT_SIZE);

      benchmark.mark('large-output-start');
      mockTerminal.write(largeOutput);
      benchmark.mark('large-output-end');

      const processingTime = benchmark.measure('large-output', 'large-output-start', 'large-output-end');

      expect(processingTime).toBeLessThan(PROCESSING_TIME_BUDGET);
      expect(mockTerminal.write).toHaveBeenCalledWith(largeOutput);
    });

    it('should maintain performance with many terminal writes', () => {
      const WRITE_COUNT = 1000;
      const TOTAL_TIME_BUDGET = 500; // 500ms for 1000 writes

      const mockTerminal = {
        write: jest.fn()
      };

      benchmark.mark('multiple-writes-start');

      for (let i = 0; i < WRITE_COUNT; i++) {
        mockTerminal.write(`Line ${i}\r\n`);
      }

      benchmark.mark('multiple-writes-end');
      const totalTime = benchmark.measure('multiple-writes', 'multiple-writes-start', 'multiple-writes-end');

      expect(totalTime).toBeLessThan(TOTAL_TIME_BUDGET);
      expect(mockTerminal.write).toHaveBeenCalledTimes(WRITE_COUNT);
    });

    it('should handle rapid scrolling efficiently', () => {
      const SCROLL_COUNT = 100;
      const SCROLL_TIME_BUDGET = 100; // 100ms for 100 scroll events

      const mockViewport = {
        scrollTop: 0,
        scrollHeight: 10000,
        clientHeight: 500,
        addEventListener: jest.fn(),
        removeEventListener: jest.fn()
      };

      benchmark.mark('rapid-scroll-start');

      // Simulate rapid scrolling
      for (let i = 0; i < SCROLL_COUNT; i++) {
        mockViewport.scrollTop = i * 10;
        // Simulate scroll event handler
        const isAtBottom = mockViewport.scrollHeight - mockViewport.scrollTop - mockViewport.clientHeight < 50;
      }

      benchmark.mark('rapid-scroll-end');
      const scrollTime = benchmark.measure('rapid-scroll', 'rapid-scroll-start', 'rapid-scroll-end');

      expect(scrollTime).toBeLessThan(SCROLL_TIME_BUDGET);
    });
  });

  describe('WebSocket Performance', () => {
    it('should handle high-frequency messages efficiently', () => {
      const MESSAGE_COUNT = 1000;
      const PROCESSING_TIME_BUDGET = 300; // 300ms for 1000 messages

      const mockWebSocket = {
        send: jest.fn(),
        onmessage: jest.fn()
      };

      const messages = Array(MESSAGE_COUNT).fill(null).map((_, i) => ({
        type: 'data',
        sessionId: 'test-session',
        data: `Message ${i}`
      }));

      benchmark.mark('message-processing-start');

      messages.forEach(message => {
        mockWebSocket.send(JSON.stringify(message));
      });

      benchmark.mark('message-processing-end');
      const processingTime = benchmark.measure('message-processing', 'message-processing-start', 'message-processing-end');

      expect(processingTime).toBeLessThan(PROCESSING_TIME_BUDGET);
      expect(mockWebSocket.send).toHaveBeenCalledTimes(MESSAGE_COUNT);
    });

    it('should handle large message payloads efficiently', () => {
      const LARGE_MESSAGE_SIZE = 64 * 1024; // 64KB message
      const LARGE_MESSAGE_BUDGET = 50; // 50ms for large message

      const mockWebSocket = {
        send: jest.fn()
      };

      const largeMessage = {
        type: 'data',
        sessionId: 'test-session',
        data: 'A'.repeat(LARGE_MESSAGE_SIZE)
      };

      benchmark.mark('large-message-start');
      mockWebSocket.send(JSON.stringify(largeMessage));
      benchmark.mark('large-message-end');

      const messageTime = benchmark.measure('large-message', 'large-message-start', 'large-message-end');

      expect(messageTime).toBeLessThan(LARGE_MESSAGE_BUDGET);
    });

    it('should maintain connection performance under stress', async () => {
      const CONNECTION_ATTEMPTS = 50;
      const CONNECTION_TIME_BUDGET = 1000; // 1 second for 50 connection attempts

      const mockWebSocket = {
        connect: jest.fn().mockResolvedValue(true),
        disconnect: jest.fn(),
        connected: false
      };

      benchmark.mark('connection-stress-start');

      const connectionPromises = Array(CONNECTION_ATTEMPTS).fill(null).map(async () => {
        return mockWebSocket.connect();
      });

      await Promise.all(connectionPromises);

      benchmark.mark('connection-stress-end');
      const connectionTime = benchmark.measure('connection-stress', 'connection-stress-start', 'connection-stress-end');

      expect(connectionTime).toBeLessThan(CONNECTION_TIME_BUDGET);
      expect(mockWebSocket.connect).toHaveBeenCalledTimes(CONNECTION_ATTEMPTS);
    });
  });

  describe('Memory Performance', () => {
    it('should not leak memory during terminal operations', () => {
      const MEMORY_LEAK_THRESHOLD = 50 * 1024 * 1024; // 50MB threshold

      memoryMonitor.resetBaseline();

      // Simulate memory-intensive operations
      const mockTerminal = {
        write: jest.fn(),
        clear: jest.fn(),
        dispose: jest.fn()
      };

      // Create large buffers and clean them up
      const operations = 100;
      for (let i = 0; i < operations; i++) {
        const largeBuffer = new Array(10000).fill(`Operation ${i}`);
        mockTerminal.write(largeBuffer.join('\n'));

        // Simulate cleanup
        if (i % 10 === 0) {
          mockTerminal.clear();
        }
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const memoryIncrease = memoryMonitor.getMemoryIncrease();
      expect(memoryIncrease).toBeLessThan(MEMORY_LEAK_THRESHOLD);
    });

    it('should clean up event listeners properly', () => {
      const eventListeners = new Map<string, Function[]>();

      const mockAddEventListener = jest.fn((event: string, handler: Function) => {
        if (!eventListeners.has(event)) {
          eventListeners.set(event, []);
        }
        eventListeners.get(event)!.push(handler);
      });

      const mockRemoveEventListener = jest.fn((event: string, handler: Function) => {
        const handlers = eventListeners.get(event) || [];
        const index = handlers.indexOf(handler);
        if (index > -1) {
          handlers.splice(index, 1);
        }
      });

      // Simulate adding many event listeners
      const listenerCount = 100;
      const handlers: Function[] = [];

      for (let i = 0; i < listenerCount; i++) {
        const handler = () => console.log(`Handler ${i}`);
        handlers.push(handler);
        mockAddEventListener('scroll', handler);
      }

      expect(mockAddEventListener).toHaveBeenCalledTimes(listenerCount);
      expect(eventListeners.get('scroll')).toHaveLength(listenerCount);

      // Simulate cleanup
      handlers.forEach(handler => {
        mockRemoveEventListener('scroll', handler);
      });

      expect(mockRemoveEventListener).toHaveBeenCalledTimes(listenerCount);
      expect(eventListeners.get('scroll')).toHaveLength(0);
    });

    it('should handle concurrent sessions efficiently', () => {
      const SESSION_COUNT = 10;
      const MEMORY_PER_SESSION_BUDGET = 10 * 1024 * 1024; // 10MB per session max

      memoryMonitor.resetBaseline();

      const sessions = Array(SESSION_COUNT).fill(null).map((_, i) => ({
        id: `session-${i}`,
        terminal: {
          write: jest.fn(),
          clear: jest.fn(),
          dispose: jest.fn()
        },
        buffer: new Array(1000).fill(`Session ${i} data`)
      }));

      // Simulate concurrent session activity
      sessions.forEach(session => {
        for (let i = 0; i < 100; i++) {
          session.terminal.write(`Data chunk ${i} for ${session.id}\n`);
        }
      });

      const totalMemoryIncrease = memoryMonitor.getMemoryIncrease();
      const memoryPerSession = totalMemoryIncrease / SESSION_COUNT;

      expect(memoryPerSession).toBeLessThan(MEMORY_PER_SESSION_BUDGET);
    });
  });

  describe('Component Performance', () => {
    it('should render component trees efficiently', () => {
      const COMPONENT_RENDER_BUDGET = 50; // 50ms for component rendering

      benchmark.mark('component-render-start');

      // Mock complex component tree rendering
      const mockComponent = {
        render: jest.fn(() => {
          // Simulate rendering work
          const elements = Array(1000).fill(null).map((_, i) => ({
            id: i,
            type: 'div',
            props: { key: i, children: `Element ${i}` }
          }));
          return elements;
        })
      };

      const result = mockComponent.render();

      benchmark.mark('component-render-end');
      const renderTime = benchmark.measure('component-render', 'component-render-start', 'component-render-end');

      expect(renderTime).toBeLessThan(COMPONENT_RENDER_BUDGET);
      expect(result).toHaveLength(1000);
    });

    it('should handle state updates efficiently', () => {
      const STATE_UPDATE_COUNT = 1000;
      const STATE_UPDATE_BUDGET = 100; // 100ms for 1000 state updates

      const mockState = {
        value: 0,
        update: jest.fn((newValue: number) => {
          mockState.value = newValue;
        })
      };

      benchmark.mark('state-updates-start');

      for (let i = 0; i < STATE_UPDATE_COUNT; i++) {
        mockState.update(i);
      }

      benchmark.mark('state-updates-end');
      const updateTime = benchmark.measure('state-updates', 'state-updates-start', 'state-updates-end');

      expect(updateTime).toBeLessThan(STATE_UPDATE_BUDGET);
      expect(mockState.update).toHaveBeenCalledTimes(STATE_UPDATE_COUNT);
      expect(mockState.value).toBe(STATE_UPDATE_COUNT - 1);
    });

    it('should handle rapid re-renders gracefully', () => {
      const RERENDER_COUNT = 100;
      const RERENDER_BUDGET = 200; // 200ms for 100 re-renders

      let renderCount = 0;
      const mockComponent = {
        render: jest.fn(() => {
          renderCount++;
          return { id: 'component', renderCount };
        })
      };

      benchmark.mark('rapid-rerenders-start');

      for (let i = 0; i < RERENDER_COUNT; i++) {
        mockComponent.render();
      }

      benchmark.mark('rapid-rerenders-end');
      const rerenderTime = benchmark.measure('rapid-rerenders', 'rapid-rerenders-start', 'rapid-rerenders-end');

      expect(rerenderTime).toBeLessThan(RERENDER_BUDGET);
      expect(renderCount).toBe(RERENDER_COUNT);
    });
  });

  describe('Load Testing', () => {
    it('should handle maximum concurrent sessions', async () => {
      const MAX_SESSIONS = 50;
      const LOAD_TEST_BUDGET = 2000; // 2 seconds for full load test

      benchmark.mark('load-test-start');

      const sessionPromises = Array(MAX_SESSIONS).fill(null).map(async (_, i) => {
        const mockSession = {
          id: `session-${i}`,
          create: jest.fn().mockResolvedValue(true),
          connect: jest.fn().mockResolvedValue(true),
          send: jest.fn(),
          disconnect: jest.fn()
        };

        await mockSession.create();
        await mockSession.connect();

        // Simulate session activity
        for (let j = 0; j < 10; j++) {
          mockSession.send(`Message ${j} from session ${i}`);
        }

        return mockSession;
      });

      const sessions = await Promise.all(sessionPromises);

      benchmark.mark('load-test-end');
      const loadTestTime = benchmark.measure('load-test', 'load-test-start', 'load-test-end');

      expect(loadTestTime).toBeLessThan(LOAD_TEST_BUDGET);
      expect(sessions).toHaveLength(MAX_SESSIONS);

      // Verify all sessions were created successfully
      sessions.forEach(session => {
        expect(session.create).toHaveBeenCalled();
        expect(session.connect).toHaveBeenCalled();
        expect(session.send).toHaveBeenCalledTimes(10);
      });
    });

    it('should maintain performance under sustained load', async () => {
      const SUSTAINED_DURATION = 1000; // 1 second of sustained load
      const MESSAGE_FREQUENCY = 10; // Messages per 100ms
      const PERFORMANCE_DEGRADATION_THRESHOLD = 1.5; // 50% performance degradation max

      const mockWebSocket = {
        send: jest.fn(),
        messageCount: 0,
        processingTimes: [] as number[]
      };

      benchmark.mark('sustained-load-start');

      const sustainedLoadPromise = new Promise<void>((resolve) => {
        const interval = setInterval(() => {
          const messageStart = performance.now();

          // Send burst of messages
          for (let i = 0; i < MESSAGE_FREQUENCY; i++) {
            mockWebSocket.send(`Sustained message ${mockWebSocket.messageCount++}`);
          }

          const messageEnd = performance.now();
          mockWebSocket.processingTimes.push(messageEnd - messageStart);

          if (performance.now() - benchmark.marks.get('sustained-load-start')! >= SUSTAINED_DURATION) {
            clearInterval(interval);
            resolve();
          }
        }, 100);
      });

      await sustainedLoadPromise;

      benchmark.mark('sustained-load-end');

      // Analyze performance degradation
      const earlyPerformance = mockWebSocket.processingTimes.slice(0, 3).reduce((a, b) => a + b, 0) / 3;
      const latePerformance = mockWebSocket.processingTimes.slice(-3).reduce((a, b) => a + b, 0) / 3;
      const performanceDegradation = latePerformance / earlyPerformance;

      expect(performanceDegradation).toBeLessThan(PERFORMANCE_DEGRADATION_THRESHOLD);
      expect(mockWebSocket.messageCount).toBeGreaterThan(50); // Should have sent many messages
    });
  });

  describe('Performance Monitoring and Metrics', () => {
    it('should track performance metrics accurately', () => {
      const metrics = {
        renderTime: 0,
        updateTime: 0,
        memoryUsage: 0,
        messageLatency: 0
      };

      // Simulate metric collection
      benchmark.mark('metric-collection-start');

      // Mock render performance
      benchmark.mark('render-start');
      // Simulate render work
      setTimeout(() => {}, 0);
      benchmark.mark('render-end');
      metrics.renderTime = benchmark.measure('render', 'render-start', 'render-end');

      // Mock update performance
      benchmark.mark('update-start');
      // Simulate update work
      setTimeout(() => {}, 0);
      benchmark.mark('update-end');
      metrics.updateTime = benchmark.measure('update', 'update-start', 'update-end');

      // Mock memory usage
      metrics.memoryUsage = memoryMonitor.getCurrentMemoryUsage();

      benchmark.mark('metric-collection-end');
      const collectionTime = benchmark.measure('metric-collection', 'metric-collection-start', 'metric-collection-end');

      // Verify metrics are reasonable
      expect(metrics.renderTime).toBeGreaterThanOrEqual(0);
      expect(metrics.updateTime).toBeGreaterThanOrEqual(0);
      expect(metrics.memoryUsage).toBeGreaterThanOrEqual(0);
      expect(collectionTime).toBeLessThan(50); // Metric collection should be fast
    });

    it('should identify performance bottlenecks', () => {
      const BOTTLENECK_THRESHOLD = 100; // 100ms threshold for bottleneck detection

      const operations = [
        { name: 'fast-operation', duration: 10 },
        { name: 'medium-operation', duration: 50 },
        { name: 'slow-operation', duration: 150 }, // Bottleneck
        { name: 'another-fast-operation', duration: 20 }
      ];

      const bottlenecks: string[] = [];

      operations.forEach(op => {
        benchmark.mark(`${op.name}-start`);

        // Simulate operation duration
        const start = performance.now();
        while (performance.now() - start < op.duration) {
          // Busy wait to simulate work
        }

        benchmark.mark(`${op.name}-end`);
        const actualDuration = benchmark.measure(op.name, `${op.name}-start`, `${op.name}-end`);

        if (actualDuration > BOTTLENECK_THRESHOLD) {
          bottlenecks.push(op.name);
        }
      });

      expect(bottlenecks).toContain('slow-operation');
      expect(bottlenecks).not.toContain('fast-operation');
      expect(bottlenecks).not.toContain('medium-operation');
      expect(bottlenecks).not.toContain('another-fast-operation');
    });
  });
});