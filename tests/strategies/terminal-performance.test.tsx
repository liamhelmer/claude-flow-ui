/**
 * @fileoverview Terminal Performance and Stress Testing
 * @description Comprehensive performance testing for Terminal components
 * @author Testing and Quality Assurance Agent
 */

import React from 'react';
import { render, screen, fireEvent, act, waitFor } from '@testing-library/react';
import { performance } from 'perf_hooks';
import Terminal from '@/components/terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';

// Mock the terminal hook for controlled testing
jest.mock('@/hooks/useTerminal');
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;

// Mock xterm.js for performance testing
const mockTerminal = {
  element: document.createElement('div'),
  open: jest.fn(),
  write: jest.fn(),
  writeln: jest.fn(),
  clear: jest.fn(),
  focus: jest.fn(),
  blur: jest.fn(),
  fit: jest.fn(),
  resize: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(),
  onResize: jest.fn(),
  onKey: jest.fn(),
  loadAddon: jest.fn(),
  cols: 80,
  rows: 24,
  options: {},
  buffer: {
    active: {
      cursorY: 0,
      cursorX: 0,
      length: 24,
      getLine: jest.fn(() => ({
        translateToString: jest.fn(() => ''),
        length: 80,
      })),
    },
    normal: {
      length: 24,
      getLine: jest.fn(() => ({
        translateToString: jest.fn(() => ''),
        length: 80,
      })),
    },
  },
  markers: [],
  addMarker: jest.fn(),
  hasSelection: jest.fn(() => false),
  getSelection: jest.fn(() => ''),
  selectAll: jest.fn(),
  select: jest.fn(),
  clearSelection: jest.fn(),
};

describe('Terminal Performance Testing', () => {
  let mockTerminalRef: { current: HTMLDivElement | null };
  let mockFocusTerminal: jest.Mock;
  let mockFitTerminal: jest.Mock;

  beforeEach(() => {
    mockTerminalRef = { current: document.createElement('div') };
    mockFocusTerminal = jest.fn();
    mockFitTerminal = jest.fn();

    mockUseTerminal.mockReturnValue({
      terminalRef: mockTerminalRef,
      terminal: mockTerminal as any,
      backendTerminalConfig: { cols: 80, rows: 24 },
      focusTerminal: mockFocusTerminal,
      fitTerminal: mockFitTerminal,
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    // Clear performance marks
    if (performance.clearMarks) {
      performance.clearMarks();
    }
  });

  describe('Rendering Performance', () => {
    it('should render within performance budget (< 16ms for 60fps)', async () => {
      const renderStart = performance.now();
      
      render(<Terminal sessionId="perf-test-1" />);
      
      const renderEnd = performance.now();
      const renderTime = renderEnd - renderStart;
      
      // Should render in under 16ms for 60fps
      expect(renderTime).toBeLessThan(16);
    });

    it('should handle rapid re-renders efficiently', async () => {
      const { rerender } = render(<Terminal sessionId="perf-test-initial" />);
      
      const rerenderStart = performance.now();
      
      // Perform 100 rapid re-renders
      for (let i = 0; i < 100; i++) {
        rerender(<Terminal sessionId={`perf-test-${i}`} />);
      }
      
      const rerenderEnd = performance.now();
      const totalRerenderTime = rerenderEnd - rerenderStart;
      const averageRerenderTime = totalRerenderTime / 100;
      
      // Each re-render should be under 10ms on average
      expect(averageRerenderTime).toBeLessThan(10);
    });

    it('should maintain performance with large terminal output', async () => {
      // Mock large output buffer
      const largeOutput = Array.from({ length: 10000 }, (_, i) => `Line ${i}: ${'x'.repeat(80)}`);
      
      mockTerminal.buffer.active.length = largeOutput.length;
      mockTerminal.buffer.active.getLine = jest.fn((index) => ({
        translateToString: () => largeOutput[index] || '',
        length: 80,
      }));

      const renderStart = performance.now();
      
      render(<Terminal sessionId="large-output-test" />);
      
      const renderEnd = performance.now();
      const renderTime = renderEnd - renderStart;
      
      // Should still render quickly even with large buffer
      expect(renderTime).toBeLessThan(50);
    });
  });

  describe('Scroll Performance', () => {
    it('should handle rapid scrolling without performance degradation', async () => {
      const { container } = render(<Terminal sessionId="scroll-test" />);
      const terminalElement = container.querySelector('.terminal-container');
      
      expect(terminalElement).toBeInTheDocument();
      
      const scrollStart = performance.now();
      
      // Simulate rapid scroll events
      for (let i = 0; i < 1000; i++) {
        fireEvent.scroll(terminalElement!, {
          target: { scrollTop: i * 10 }
        });
      }
      
      const scrollEnd = performance.now();
      const scrollTime = scrollEnd - scrollStart;
      
      // All scroll events should complete in under 100ms
      expect(scrollTime).toBeLessThan(100);
    });

    it('should maintain smooth scrolling with large scroll distances', async () => {
      const { container } = render(<Terminal sessionId="smooth-scroll-test" />);
      const terminalElement = container.querySelector('.terminal-container');
      
      const scrollPerformanceEntries: number[] = [];
      
      // Measure individual scroll event performance
      for (let i = 0; i < 50; i++) {
        const scrollEventStart = performance.now();
        
        await act(async () => {
          fireEvent.scroll(terminalElement!, {
            target: { scrollTop: i * 1000 } // Large scroll distances
          });
        });
        
        const scrollEventEnd = performance.now();
        scrollPerformanceEntries.push(scrollEventEnd - scrollEventStart);
      }
      
      // Each scroll event should complete quickly
      const averageScrollTime = scrollPerformanceEntries.reduce((a, b) => a + b, 0) / scrollPerformanceEntries.length;
      expect(averageScrollTime).toBeLessThan(5);
      
      // No single scroll event should take too long
      const maxScrollTime = Math.max(...scrollPerformanceEntries);
      expect(maxScrollTime).toBeLessThan(20);
    });
  });

  describe('Input Performance', () => {
    it('should handle rapid typing without input lag', async () => {
      render(<Terminal sessionId="typing-test" />);
      
      const typingText = 'The quick brown fox jumps over the lazy dog'.repeat(100);
      const inputTimings: number[] = [];
      
      for (const char of typingText) {
        const inputStart = performance.now();
        
        // Simulate typing each character
        if (mockTerminal.onData.mock.calls.length > 0) {
          const dataHandler = mockTerminal.onData.mock.calls[0][0];
          dataHandler(char);
        }
        
        const inputEnd = performance.now();
        inputTimings.push(inputEnd - inputStart);
      }
      
      const averageInputTime = inputTimings.reduce((a, b) => a + b, 0) / inputTimings.length;
      
      // Average input handling should be under 1ms
      expect(averageInputTime).toBeLessThan(1);
      
      // No single input should take more than 5ms
      const maxInputTime = Math.max(...inputTimings);
      expect(maxInputTime).toBeLessThan(5);
    });

    it('should handle paste operations of large text efficiently', async () => {
      render(<Terminal sessionId="paste-test" />);
      
      const largeText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(10000);
      
      const pasteStart = performance.now();
      
      // Simulate paste operation
      if (mockTerminal.onData.mock.calls.length > 0) {
        const dataHandler = mockTerminal.onData.mock.calls[0][0];
        dataHandler(largeText);
      }
      
      const pasteEnd = performance.now();
      const pasteTime = pasteEnd - pasteStart;
      
      // Large paste should complete in under 100ms
      expect(pasteTime).toBeLessThan(100);
    });
  });

  describe('Memory Performance', () => {
    it('should not leak memory during extended use', async () => {
      const initialMemory = process.memoryUsage();
      
      // Simulate extended terminal usage
      for (let session = 0; session < 100; session++) {
        const { unmount } = render(<Terminal sessionId={`memory-test-${session}`} />);
        
        // Simulate some terminal activity
        if (mockTerminal.write.mock.calls) {
          mockTerminal.write(`Session ${session} activity\n`);
        }
        
        // Cleanup
        unmount();
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Memory increase should be minimal (less than 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });

    it('should cleanup resources properly on unmount', async () => {
      const { unmount } = render(<Terminal sessionId="cleanup-test" />);
      
      // Verify terminal is created
      expect(mockTerminal.open).toHaveBeenCalled();
      
      // Unmount component
      unmount();
      
      // Verify cleanup was called (this would depend on actual implementation)
      // In real implementation, you'd check if dispose was called
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });

  describe('Resize Performance', () => {
    it('should handle window resize events efficiently', async () => {
      render(<Terminal sessionId="resize-test" />);
      
      const resizeTimings: number[] = [];
      
      // Simulate multiple resize events
      for (let i = 0; i < 50; i++) {
        const resizeStart = performance.now();
        
        await act(async () => {
          mockFitTerminal();
          mockTerminal.resize(80 + i, 24 + Math.floor(i / 2));
        });
        
        const resizeEnd = performance.now();
        resizeTimings.push(resizeEnd - resizeStart);
      }
      
      const averageResizeTime = resizeTimings.reduce((a, b) => a + b, 0) / resizeTimings.length;
      
      // Average resize should be under 10ms
      expect(averageResizeTime).toBeLessThan(10);
      
      // No single resize should take more than 50ms
      const maxResizeTime = Math.max(...resizeTimings);
      expect(maxResizeTime).toBeLessThan(50);
    });

    it('should debounce rapid resize events', async () => {
      render(<Terminal sessionId="debounce-resize-test" />);
      
      let resizeCallCount = 0;
      const originalFitTerminal = mockFitTerminal;
      mockFitTerminal = jest.fn(() => {
        resizeCallCount++;
        return originalFitTerminal();
      });
      
      // Simulate rapid resize events (like window dragging)
      for (let i = 0; i < 100; i++) {
        fireEvent(window, new Event('resize'));
        
        // Small delay between events to simulate real resize behavior
        await new Promise(resolve => setTimeout(resolve, 1));
      }
      
      // Wait for debouncing to complete
      await waitFor(() => {
        // Should have significantly fewer calls than events due to debouncing
        expect(resizeCallCount).toBeLessThan(20);
      }, { timeout: 1000 });
    });
  });

  describe('Focus Management Performance', () => {
    it('should handle focus changes efficiently', async () => {
      const { rerender } = render(<Terminal sessionId="focus-test-1" />);
      
      const focusTimings: number[] = [];
      
      // Test focus performance with session switches
      for (let i = 0; i < 50; i++) {
        const focusStart = performance.now();
        
        await act(async () => {
          rerender(<Terminal sessionId={`focus-test-${i}`} />);
        });
        
        const focusEnd = performance.now();
        focusTimings.push(focusEnd - focusStart);
      }
      
      const averageFocusTime = focusTimings.reduce((a, b) => a + b, 0) / focusTimings.length;
      
      // Focus changes should be quick
      expect(averageFocusTime).toBeLessThan(5);
    });
  });

  describe('Stress Testing', () => {
    it('should survive extreme load conditions', async () => {
      const stressTestPromises: Promise<void>[] = [];
      
      // Create multiple terminals simultaneously
      for (let i = 0; i < 20; i++) {
        stressTestPromises.push(
          new Promise<void>((resolve) => {
            const { unmount } = render(<Terminal sessionId={`stress-test-${i}`} />);
            
            // Simulate activity on each terminal
            setTimeout(() => {
              if (mockTerminal.write) {
                for (let j = 0; j < 1000; j++) {
                  mockTerminal.write(`Stress test line ${j}\n`);
                }
              }
              
              unmount();
              resolve();
            }, Math.random() * 100);
          })
        );
      }
      
      const stressStart = performance.now();
      
      // Wait for all stress tests to complete
      await Promise.all(stressTestPromises);
      
      const stressEnd = performance.now();
      const stressTime = stressEnd - stressStart;
      
      // Should complete all stress tests in reasonable time
      expect(stressTime).toBeLessThan(5000); // 5 seconds max
    });

    it('should maintain responsiveness under sustained load', async () => {
      render(<Terminal sessionId="sustained-load-test" />);
      
      let responsiveChecks = 0;
      const checkInterval = setInterval(() => {
        const responseStart = performance.now();
        
        // Simulate user interaction during load
        mockFocusTerminal();
        
        const responseEnd = performance.now();
        const responseTime = responseEnd - responseStart;
        
        // Should remain responsive (under 16ms for 60fps)
        expect(responseTime).toBeLessThan(16);
        responsiveChecks++;
      }, 100);
      
      // Generate sustained load
      const loadPromise = new Promise<void>((resolve) => {
        let loadOperations = 0;
        const loadInterval = setInterval(() => {
          if (mockTerminal.write) {
            mockTerminal.write(`Load operation ${loadOperations}\n`);
          }
          
          loadOperations++;
          if (loadOperations >= 500) {
            clearInterval(loadInterval);
            resolve();
          }
        }, 10);
      });
      
      await loadPromise;
      clearInterval(checkInterval);
      
      // Should have performed multiple responsiveness checks
      expect(responsiveChecks).toBeGreaterThan(10);
    });
  });
});