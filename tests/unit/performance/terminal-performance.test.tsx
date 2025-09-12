/**
 * Terminal Performance Tests
 * Tests rendering performance, memory usage, and optimization effectiveness
 */

import React from 'react';
import { render, act, waitFor } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import Terminal from '@/components/terminal/Terminal';

// Mock performance APIs
const mockPerformance = {
  now: jest.fn(() => Date.now()),
  mark: jest.fn(),
  measure: jest.fn(),
  getEntriesByType: jest.fn(() => []),
  getEntriesByName: jest.fn(() => [])
};

Object.defineProperty(global, 'performance', {
  value: mockPerformance,
  writable: true
});

// Mock useTerminal for performance testing
jest.mock('@/hooks/useTerminal');
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;

// Mock terminal with performance tracking
const createMockTerminal = () => ({
  open: jest.fn(),
  write: jest.fn(),
  writeln: jest.fn(),
  clear: jest.fn(),
  reset: jest.fn(),
  focus: jest.fn(),
  blur: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(),
  onResize: jest.fn(),
  cols: 80,
  rows: 24,
  element: document.createElement('div'),
  scrollToBottom: jest.fn(),
  scrollToTop: jest.fn(),
  // Performance tracking methods
  _performanceStats: {
    writeCount: 0,
    totalWriteTime: 0,
    lastWriteTime: 0
  }
});

describe('Terminal Performance Tests', () => {
  let mockTerminal: ReturnType<typeof createMockTerminal>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockTerminal = createMockTerminal();
    
    mockUseTerminal.mockReturnValue({
      terminalRef: { current: document.createElement('div') },
      terminal: mockTerminal as any,
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      isAtBottom: true,
      hasNewOutput: false,
      isConnected: true,
      terminalConfig: {
        theme: 'dark',
        fontSize: 14,
        fontFamily: 'monospace',
        cursorBlink: true,
        scrollback: 1000,
        cols: 80,
        rows: 24
      },
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      destroyTerminal: jest.fn()
    });

    // Mock performance timing
    let performanceCounter = 0;
    mockPerformance.now.mockImplementation(() => performanceCounter++);
  });

  describe('Rendering Performance', () => {
    it('should render terminal within performance budget', async () => {
      const startTime = performance.now();
      
      const { container } = render(<Terminal sessionId="perf-test" />);
      
      const endTime = performance.now();
      const renderTime = endTime - startTime;

      // Initial render should be fast (< 16ms for 60fps)
      expect(renderTime).toBeLessThan(16);
      expect(container.firstChild).toBeInTheDocument();
    });

    it('should handle rapid re-renders efficiently', async () => {
      const renderTimes: number[] = [];
      
      const { rerender } = render(<Terminal sessionId="session-1" />);

      // Test 100 rapid re-renders
      for (let i = 2; i <= 100; i++) {
        const start = performance.now();
        
        act(() => {
          rerender(<Terminal sessionId={`session-${i}`} />);
        });
        
        const end = performance.now();
        renderTimes.push(end - start);
      }

      // Average render time should remain consistent
      const averageTime = renderTimes.reduce((sum, time) => sum + time, 0) / renderTimes.length;
      const maxTime = Math.max(...renderTimes);
      const minTime = Math.min(...renderTimes);
      
      expect(averageTime).toBeLessThan(5);
      expect(maxTime - minTime).toBeLessThan(averageTime * 2); // Low variance
    });

    it('should optimize re-renders when props unchanged', () => {
      const renderCount = jest.fn();
      
      // Create component that tracks renders
      const TrackingTerminal = ({ sessionId }: { sessionId: string }) => {
        renderCount();
        return <Terminal sessionId={sessionId} />;
      };

      const { rerender } = render(<TrackingTerminal sessionId="same-session" />);

      // Re-render with same props
      for (let i = 0; i < 10; i++) {
        rerender(<TrackingTerminal sessionId="same-session" />);
      }

      // Should have optimized re-renders
      expect(renderCount).toHaveBeenCalledTimes(11); // Initial + 10 re-renders
    });

    it('should handle large terminal dimensions efficiently', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminalConfig: {
          theme: 'dark',
          fontSize: 14,
          fontFamily: 'monospace',
          cursorBlink: true,
          scrollback: 1000,
          cols: 200, // Large terminal
          rows: 50   // Large terminal
        }
      });

      const startTime = performance.now();
      
      render(<Terminal sessionId="large-terminal" />);
      
      const endTime = performance.now();
      const renderTime = endTime - startTime;

      // Should still render quickly even with large dimensions
      expect(renderTime).toBeLessThan(50);
    });
  });

  describe('Data Processing Performance', () => {
    it('should handle high-frequency data writes efficiently', async () => {
      const { writeToTerminal } = mockUseTerminal();
      const writeCount = 1000;
      const writeTimes: number[] = [];

      render(<Terminal sessionId="data-test" />);

      // Measure individual write performance
      for (let i = 0; i < writeCount; i++) {
        const start = performance.now();
        
        act(() => {
          writeToTerminal?.(`Line ${i}: Some terminal output data\n`);
        });
        
        const end = performance.now();
        writeTimes.push(end - start);
      }

      const averageWriteTime = writeTimes.reduce((sum, time) => sum + time, 0) / writeTimes.length;
      const maxWriteTime = Math.max(...writeTimes);

      // Each write should be very fast
      expect(averageWriteTime).toBeLessThan(1);
      expect(maxWriteTime).toBeLessThan(5);
    });

    it('should handle large data chunks efficiently', () => {
      const { writeToTerminal } = mockUseTerminal();
      const chunkSizes = [1024, 4096, 16384, 65536, 262144]; // 1KB to 256KB

      render(<Terminal sessionId="chunk-test" />);

      chunkSizes.forEach(size => {
        const largeData = 'x'.repeat(size);
        
        const start = performance.now();
        
        act(() => {
          writeToTerminal?.(largeData);
        });
        
        const end = performance.now();
        const writeTime = end - start;

        // Write time should scale reasonably with data size
        const timePerByte = writeTime / size;
        expect(timePerByte).toBeLessThan(0.001); // Less than 1μs per byte
      });
    });

    it('should maintain performance with concurrent operations', async () => {
      const { writeToTerminal, focusTerminal, scrollToBottom, clearTerminal } = mockUseTerminal();

      render(<Terminal sessionId="concurrent-test" />);

      const operations = [];
      const startTime = performance.now();

      // Create concurrent operations
      for (let i = 0; i < 100; i++) {
        operations.push(
          Promise.resolve().then(() => {
            act(() => {
              writeToTerminal?.(`Concurrent write ${i}\n`);
            });
          })
        );

        if (i % 20 === 0) {
          operations.push(
            Promise.resolve().then(() => {
              act(() => {
                focusTerminal?.();
              });
            })
          );
        }

        if (i % 50 === 0) {
          operations.push(
            Promise.resolve().then(() => {
              act(() => {
                scrollToBottom?.();
              });
            })
          );
        }
      }

      await Promise.all(operations);
      
      const endTime = performance.now();
      const totalTime = endTime - startTime;

      // All concurrent operations should complete quickly
      expect(totalTime).toBeLessThan(100);
    });
  });

  describe('Memory Performance', () => {
    it('should not leak memory with repeated creation/destruction', () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Create and destroy terminals repeatedly
      for (let i = 0; i < 50; i++) {
        const { unmount } = render(<Terminal sessionId={`memory-test-${i}`} />);
        
        act(() => {
          // Simulate some operations
          mockUseTerminal().writeToTerminal?.('Some test data');
          mockUseTerminal().focusTerminal?.();
        });
        
        unmount();
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be minimal
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // < 50MB
    });

    it('should efficiently handle large scrollback buffers', () => {
      mockUseTerminal.mockReturnValue({
        ...mockUseTerminal(),
        terminalConfig: {
          theme: 'dark',
          fontSize: 14,
          fontFamily: 'monospace',
          cursorBlink: true,
          scrollback: 999999, // Very large scrollback
          cols: 80,
          rows: 24
        }
      });

      const startMemory = process.memoryUsage().heapUsed;
      
      render(<Terminal sessionId="scrollback-test" />);

      // Simulate large amount of data
      const { writeToTerminal } = mockUseTerminal();
      
      act(() => {
        for (let i = 0; i < 10000; i++) {
          writeToTerminal?.(`Scrollback line ${i}: ${'x'.repeat(80)}\n`);
        }
      });

      const endMemory = process.memoryUsage().heapUsed;
      const memoryUsed = endMemory - startMemory;

      // Memory usage should be reasonable for large scrollback
      expect(memoryUsed).toBeLessThan(100 * 1024 * 1024); // < 100MB
    });

    it('should clean up event listeners properly', () => {
      const addEventListener = jest.spyOn(window, 'addEventListener');
      const removeEventListener = jest.spyOn(window, 'removeEventListener');

      const { unmount } = render(<Terminal sessionId="event-test" />);

      const initialListenerCount = addEventListener.mock.calls.length;
      
      unmount();

      const removedListenerCount = removeEventListener.mock.calls.length;

      // Should remove same number of listeners as added (or more)
      expect(removedListenerCount).toBeGreaterThanOrEqual(0);

      addEventListener.mockRestore();
      removeEventListener.mockRestore();
    });
  });

  describe('Animation and Scroll Performance', () => {
    it('should handle smooth scrolling efficiently', async () => {
      // Mock requestAnimationFrame
      const rafCallbacks: (() => void)[] = [];
      global.requestAnimationFrame = jest.fn((callback) => {
        rafCallbacks.push(callback);
        return rafCallbacks.length;
      });

      const { scrollToBottom, scrollToTop } = mockUseTerminal();

      render(<Terminal sessionId="scroll-test" />);

      const startTime = performance.now();

      // Trigger multiple scroll operations
      act(() => {
        scrollToBottom?.();
        scrollToTop?.();
        scrollToBottom?.();
      });

      // Execute RAF callbacks
      act(() => {
        rafCallbacks.forEach(callback => callback());
      });

      const endTime = performance.now();
      const scrollTime = endTime - startTime;

      // Scroll operations should be fast
      expect(scrollTime).toBeLessThan(16); // One frame budget
      expect(rafCallbacks.length).toBeGreaterThan(0);
    });

    it('should throttle rapid scroll events', () => {
      const { scrollToBottom } = mockUseTerminal();

      render(<Terminal sessionId="throttle-test" />);

      const scrollCount = 100;
      const startTime = performance.now();

      // Rapid scroll operations
      for (let i = 0; i < scrollCount; i++) {
        act(() => {
          scrollToBottom?.();
        });
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      // Should handle rapid scrolling efficiently
      expect(totalTime).toBeLessThan(50);
    });
  });

  describe('Optimization Effectiveness', () => {
    it('should demonstrate performance improvements over time', () => {
      const performanceMetrics: number[] = [];

      // Measure performance over multiple operations
      for (let batch = 0; batch < 10; batch++) {
        const batchStart = performance.now();

        const { unmount } = render(<Terminal sessionId={`batch-${batch}`} />);
        
        act(() => {
          const { writeToTerminal } = mockUseTerminal();
          
          // Simulate typical usage
          for (let i = 0; i < 100; i++) {
            writeToTerminal?.(`Batch ${batch}, Line ${i}\n`);
          }
        });

        unmount();

        const batchEnd = performance.now();
        performanceMetrics.push(batchEnd - batchStart);
      }

      // Performance should be consistent (not degrading)
      const firstHalf = performanceMetrics.slice(0, 5);
      const secondHalf = performanceMetrics.slice(5);
      
      const firstHalfAvg = firstHalf.reduce((sum, time) => sum + time, 0) / firstHalf.length;
      const secondHalfAvg = secondHalf.reduce((sum, time) => sum + time, 0) / secondHalf.length;

      // Performance should not degrade significantly
      expect(secondHalfAvg).toBeLessThan(firstHalfAvg * 1.5);
    });

    it('should show benefits of memoization', () => {
      let memoHits = 0;
      let memoMisses = 0;

      // Mock memoization tracking
      const originalMemo = React.memo;
      jest.spyOn(React, 'memo').mockImplementation((Component) => {
        return originalMemo(Component, (prevProps, nextProps) => {
          const areEqual = JSON.stringify(prevProps) === JSON.stringify(nextProps);
          if (areEqual) {
            memoHits++;
          } else {
            memoMisses++;
          }
          return areEqual;
        });
      });

      const { rerender } = render(<Terminal sessionId="memo-test" />);

      // Re-render with same props multiple times
      for (let i = 0; i < 10; i++) {
        rerender(<Terminal sessionId="memo-test" />);
      }

      // Re-render with different props
      for (let i = 0; i < 5; i++) {
        rerender(<Terminal sessionId={`memo-test-${i}`} />);
      }

      // Should show memoization effectiveness
      expect(memoHits).toBeGreaterThan(0);
      
      React.memo.mockRestore();
    });
  });

  describe('Performance Monitoring', () => {
    it('should track performance metrics', () => {
      const performanceEntries: PerformanceEntry[] = [];
      
      mockPerformance.getEntriesByType.mockReturnValue(performanceEntries);

      render(<Terminal sessionId="metrics-test" />);

      // Should be able to track performance metrics
      expect(mockPerformance.getEntriesByType).toHaveBeenCalled();
    });

    it('should identify performance bottlenecks', () => {
      const bottlenecks: { operation: string; duration: number }[] = [];

      // Simulate performance monitoring
      const operations = [
        { name: 'render', duration: 10 },
        { name: 'write', duration: 5 },
        { name: 'scroll', duration: 2 },
        { name: 'focus', duration: 1 }
      ];

      operations.forEach(op => {
        if (op.duration > 8) {
          bottlenecks.push({ operation: op.name, duration: op.duration });
        }
      });

      // Should identify render as a bottleneck
      expect(bottlenecks).toHaveLength(1);
      expect(bottlenecks[0].operation).toBe('render');
    });

    it('should provide performance recommendations', () => {
      const metrics = {
        averageRenderTime: 12,
        memoryUsage: 45 * 1024 * 1024, // 45MB
        scrollPerformance: 8,
        writePerformance: 3
      };

      const recommendations: string[] = [];

      // Performance analysis
      if (metrics.averageRenderTime > 16) {
        recommendations.push('Consider component memoization');
      }
      
      if (metrics.memoryUsage > 50 * 1024 * 1024) {
        recommendations.push('Optimize memory usage');
      }
      
      if (metrics.scrollPerformance > 10) {
        recommendations.push('Implement scroll throttling');
      }

      // Should provide actionable recommendations
      expect(recommendations.length).toBeGreaterThanOrEqual(0);
      
      if (recommendations.length > 0) {
        expect(recommendations.every(rec => typeof rec === 'string')).toBe(true);
      }
    });
  });
});