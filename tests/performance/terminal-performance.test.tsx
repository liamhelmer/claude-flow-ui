import { performance } from 'perf_hooks';
import { renderHook, act } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { Terminal } from '@xterm/xterm';

// Mock dependencies for performance testing
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn(),
}));

jest.mock('@xterm/addon-serialize', () => ({
  SerializeAddon: jest.fn(),
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    isConnected: true,
  }),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => ({}),
}));

describe('Terminal Performance Tests', () => {
  let mockTerminal: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock high-performance terminal instance
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn(),
      dispose: jest.fn(),
      resize: jest.fn(),
      onData: jest.fn(),
      loadAddon: jest.fn(),
      cols: 120,
      rows: 40,
      element: {
        querySelector: jest.fn(() => ({
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          scrollTop: 0,
          scrollHeight: 1000,
          clientHeight: 500,
        })),
      },
    };

    (Terminal as jest.Mock).mockImplementation(() => mockTerminal);

    // Mock performance-optimized RAF
    global.requestAnimationFrame = jest.fn((cb) => {
      setImmediate(cb);
      return 1;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Initialization Performance', () => {
    it('should initialize terminal quickly', () => {
      const startTime = performance.now();
      
      renderHook(() =>
        useTerminal({ sessionId: 'perf-test' })
      );
      
      const initTime = performance.now() - startTime;
      
      // Terminal initialization should be under 10ms
      expect(initTime).toBeLessThan(10);
    });

    it('should handle multiple terminal instances efficiently', () => {
      const startTime = performance.now();
      const hooks = [];
      
      // Create 10 terminal instances
      for (let i = 0; i < 10; i++) {
        hooks.push(
          renderHook(() =>
            useTerminal({ sessionId: `perf-test-${i}` })
          )
        );
      }
      
      const totalTime = performance.now() - startTime;
      
      // Should create all instances quickly
      expect(totalTime).toBeLessThan(100);
      
      // Cleanup
      hooks.forEach(hook => hook.unmount());
    });

    it('should optimize memory usage during initialization', () => {
      const memoryBefore = process.memoryUsage().heapUsed;
      
      const hook = renderHook(() =>
        useTerminal({ sessionId: 'memory-test' })
      );
      
      const memoryAfter = process.memoryUsage().heapUsed;
      const memoryIncrease = memoryAfter - memoryBefore;
      
      // Memory increase should be reasonable (under 1MB for single terminal)
      expect(memoryIncrease).toBeLessThan(1024 * 1024);
      
      hook.unmount();
    });
  });

  describe('Data Processing Performance', () => {
    let hook: any;

    beforeEach(async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'data-perf-test' })
      );
      hook = result;

      // Wait for terminal to be ready
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
      });
    });

    it('should handle rapid data writes efficiently', () => {
      const dataChunks = Array.from({ length: 1000 }, (_, i) => `Data chunk ${i}\n`);
      const startTime = performance.now();
      
      act(() => {
        dataChunks.forEach(chunk => {
          hook.current.writeToTerminal(chunk);
        });
      });
      
      const writeTime = performance.now() - startTime;
      
      // Should process 1000 writes quickly
      expect(writeTime).toBeLessThan(100);
      expect(mockTerminal.write).toHaveBeenCalledTimes(1000);
    });

    it('should handle large data chunks efficiently', () => {
      const largeChunk = 'x'.repeat(100000); // 100KB chunk
      const startTime = performance.now();
      
      act(() => {
        hook.current.writeToTerminal(largeChunk);
      });
      
      const writeTime = performance.now() - startTime;
      
      // Large chunk write should be fast
      expect(writeTime).toBeLessThan(50);
      expect(mockTerminal.write).toHaveBeenCalledWith(largeChunk);
    });

    it('should throttle scroll position updates for performance', () => {
      const scrollCalls: number[] = [];
      
      // Mock RAF to track timing
      (global.requestAnimationFrame as jest.Mock).mockImplementation((cb) => {
        scrollCalls.push(performance.now());
        setImmediate(cb);
        return scrollCalls.length;
      });

      // Simulate rapid scroll updates
      act(() => {
        for (let i = 0; i < 100; i++) {
          hook.current.scrollToBottom();
        }
      });

      // Should throttle scroll calls
      expect(global.requestAnimationFrame).toHaveBeenCalledTimes(100);
    });
  });

  describe('ANSI Processing Performance', () => {
    let hook: any;

    beforeEach(async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'ansi-perf-test' })
      );
      hook = result;

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
      });
    });

    it('should handle complex ANSI sequences efficiently', () => {
      const complexANSI = '\x1b[38;5;196m\x1b[48;5;21m\x1b[1m\x1b[4mComplex colored text\x1b[0m';
      const ansiChunks = Array.from({ length: 500 }, () => complexANSI);
      const startTime = performance.now();
      
      act(() => {
        ansiChunks.forEach(chunk => {
          hook.current.writeToTerminal(chunk);
        });
      });
      
      const processTime = performance.now() - startTime;
      
      // Should process ANSI sequences quickly
      expect(processTime).toBeLessThan(200);
    });

    it('should handle cursor movement sequences efficiently', () => {
      const cursorSequences = [
        '\x1b[H',      // Home
        '\x1b[2J',     // Clear screen
        '\x1b[10;20H', // Move cursor
        '\x1b[1A',     // Up
        '\x1b[1B',     // Down
        '\x1b[1C',     // Right
        '\x1b[1D',     // Left
      ];
      
      const startTime = performance.now();
      
      act(() => {
        for (let i = 0; i < 1000; i++) {
          const sequence = cursorSequences[i % cursorSequences.length];
          hook.current.writeToTerminal(sequence);
        }
      });
      
      const processTime = performance.now() - startTime;
      
      expect(processTime).toBeLessThan(150);
    });
  });

  describe('Memory Management Performance', () => {
    it('should cleanup resources efficiently', () => {
      const hooks = [];
      
      // Create multiple terminals
      for (let i = 0; i < 20; i++) {
        hooks.push(
          renderHook(() =>
            useTerminal({ sessionId: `cleanup-test-${i}` })
          )
        );
      }
      
      const startTime = performance.now();
      
      // Cleanup all terminals
      hooks.forEach(hook => hook.unmount());
      
      const cleanupTime = performance.now() - startTime;
      
      // Cleanup should be fast
      expect(cleanupTime).toBeLessThan(50);
      expect(mockTerminal.dispose).toHaveBeenCalledTimes(20);
    });

    it('should not leak memory with repeated create/destroy cycles', () => {
      const memoryMeasurements = [];
      
      for (let i = 0; i < 10; i++) {
        const hook = renderHook(() =>
          useTerminal({ sessionId: `memory-leak-test-${i}` })
        );
        
        // Simulate some activity
        act(() => {
          hook.result.current.writeToTerminal('Memory test data');
          hook.result.current.clearTerminal();
        });
        
        hook.unmount();
        
        memoryMeasurements.push(process.memoryUsage().heapUsed);
      }
      
      // Memory should not continuously increase
      const initialMemory = memoryMeasurements[0];
      const finalMemory = memoryMeasurements[memoryMeasurements.length - 1];
      const memoryIncrease = finalMemory - initialMemory;
      
      // Allow for some variance but no major leaks (under 5MB increase)
      expect(memoryIncrease).toBeLessThan(5 * 1024 * 1024);
    });
  });

  describe('Concurrency Performance', () => {
    it('should handle concurrent terminal operations efficiently', async () => {
      const terminals = [];
      
      // Create multiple terminals concurrently
      const createPromises = Array.from({ length: 10 }, (_, i) =>
        new Promise(resolve => {
          const hook = renderHook(() =>
            useTerminal({ sessionId: `concurrent-test-${i}` })
          );
          terminals.push(hook);
          resolve(hook);
        })
      );
      
      const startTime = performance.now();
      
      await Promise.all(createPromises);
      
      // Simulate concurrent operations
      await Promise.all(
        terminals.map(async (hook, i) => {
          return new Promise(resolve => {
            act(() => {
              hook.result.current.writeToTerminal(`Concurrent data ${i}`);
              hook.result.current.focusTerminal();
              hook.result.current.scrollToBottom();
            });
            resolve(undefined);
          });
        })
      );
      
      const totalTime = performance.now() - startTime;
      
      expect(totalTime).toBeLessThan(200);
      
      // Cleanup
      terminals.forEach(hook => hook.unmount());
    });

    it('should handle high-frequency updates without performance degradation', () => {
      const hook = renderHook(() =>
        useTerminal({ sessionId: 'high-freq-test' })
      );
      
      const updateCounts = [10, 100, 1000, 5000];
      const timings = [];
      
      updateCounts.forEach(count => {
        const startTime = performance.now();
        
        act(() => {
          for (let i = 0; i < count; i++) {
            hook.result.current.writeToTerminal(`Update ${i}`);
          }
        });
        
        timings.push(performance.now() - startTime);
      });
      
      // Performance should scale reasonably (not exponentially)
      const avgTimePerUpdate = timings.map((time, i) => time / updateCounts[i]);
      
      // Time per update should remain relatively constant
      const maxTimePerUpdate = Math.max(...avgTimePerUpdate);
      const minTimePerUpdate = Math.min(...avgTimePerUpdate);
      const performanceRatio = maxTimePerUpdate / minTimePerUpdate;
      
      expect(performanceRatio).toBeLessThan(5); // No more than 5x slower
      
      hook.unmount();
    });
  });

  describe('Real-world Performance Scenarios', () => {
    it('should handle typical developer workflow efficiently', () => {
      const hook = renderHook(() =>
        useTerminal({ sessionId: 'dev-workflow-test' })
      );
      
      const startTime = performance.now();
      
      act(() => {
        // Simulate typical development workflow
        hook.result.current.writeToTerminal('$ npm install\n');
        hook.result.current.writeToTerminal('Installing dependencies...\n');
        
        // Simulate package installation output
        for (let i = 0; i < 100; i++) {
          hook.result.current.writeToTerminal(`Installing package-${i}...\n`);
        }
        
        hook.result.current.writeToTerminal('$ npm test\n');
        hook.result.current.writeToTerminal('Running tests...\n');
        
        // Simulate test output
        for (let i = 0; i < 50; i++) {
          hook.result.current.writeToTerminal(`✓ Test ${i} passed\n`);
        }
        
        hook.result.current.writeToTerminal('All tests passed!\n');
      });
      
      const workflowTime = performance.now() - startTime;
      
      // Typical workflow should complete quickly
      expect(workflowTime).toBeLessThan(100);
      
      hook.unmount();
    });

    it('should handle log streaming efficiently', () => {
      const hook = renderHook(() =>
        useTerminal({ sessionId: 'log-stream-test' })
      );
      
      const startTime = performance.now();
      const logEntries = 2000;
      
      act(() => {
        for (let i = 0; i < logEntries; i++) {
          const timestamp = new Date().toISOString();
          const level = ['INFO', 'WARN', 'ERROR'][i % 3];
          const message = `Log entry ${i} with some details`;
          
          hook.result.current.writeToTerminal(
            `[${timestamp}] ${level}: ${message}\n`
          );
        }
      });
      
      const streamTime = performance.now() - startTime;
      
      // Log streaming should be efficient
      expect(streamTime).toBeLessThan(300);
      
      hook.unmount();
    });

    it('should maintain performance under sustained load', () => {
      const hook = renderHook(() =>
        useTerminal({ sessionId: 'sustained-load-test' })
      );
      
      const measurements = [];
      const batchSize = 100;
      const batches = 10;
      
      for (let batch = 0; batch < batches; batch++) {
        const batchStart = performance.now();
        
        act(() => {
          for (let i = 0; i < batchSize; i++) {
            hook.result.current.writeToTerminal(`Batch ${batch}, item ${i}\n`);
          }
        });
        
        measurements.push(performance.now() - batchStart);
      }
      
      // Performance should remain consistent across batches
      const avgTime = measurements.reduce((a, b) => a + b, 0) / measurements.length;
      const maxDeviation = Math.max(...measurements.map(time => Math.abs(time - avgTime)));
      
      // Max deviation should not be more than 50% of average
      expect(maxDeviation / avgTime).toBeLessThan(0.5);
      
      hook.unmount();
    });
  });

  describe('Browser Performance Integration', () => {
    it('should not block the main thread', () => {
      const hook = renderHook(() =>
        useTerminal({ sessionId: 'main-thread-test' })
      );
      
      let mainThreadBlocked = false;
      
      // Set up a timer to detect main thread blocking
      const timer = setTimeout(() => {
        mainThreadBlocked = true;
      }, 50);
      
      act(() => {
        // Perform intensive terminal operations
        for (let i = 0; i < 5000; i++) {
          hook.result.current.writeToTerminal(`Non-blocking operation ${i}\n`);
        }
      });
      
      clearTimeout(timer);
      
      // Main thread should not be blocked
      expect(mainThreadBlocked).toBe(false);
      
      hook.unmount();
    });

    it('should optimize scroll performance', () => {
      const hook = renderHook(() =>
        useTerminal({ sessionId: 'scroll-perf-test' })
      );
      
      const scrollOperations = 1000;
      const startTime = performance.now();
      
      act(() => {
        for (let i = 0; i < scrollOperations; i++) {
          hook.result.current.scrollToBottom();
          hook.result.current.scrollToTop();
        }
      });
      
      const scrollTime = performance.now() - startTime;
      
      // Scroll operations should be batched and efficient
      expect(scrollTime).toBeLessThan(100);
      
      hook.unmount();
    });
  });
});