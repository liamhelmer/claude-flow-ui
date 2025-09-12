/**
 * @jest-environment jsdom
 */

import { renderHook, act } from '@testing-library/react';
import { useTerminalResize } from '../useTerminalResize';

// Mock ResizeObserver
global.ResizeObserver = jest.fn().mockImplementation((callback) => ({
  observe: jest.fn().mockImplementation((element) => {
    // Store callback for manual triggering
    (element as any).__resizeCallback = callback;
  }),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Mock requestAnimationFrame
global.requestAnimationFrame = jest.fn((callback) => {
  setTimeout(callback, 16);
  return 1;
});

global.cancelAnimationFrame = jest.fn();

describe('useTerminalResize Comprehensive Tests', () => {
  let mockContainer: HTMLDivElement;
  let mockCallback: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create mock container element
    mockContainer = document.createElement('div');
    mockContainer.style.width = '800px';
    mockContainer.style.height = '600px';
    
    // Mock getBoundingClientRect
    mockContainer.getBoundingClientRect = jest.fn(() => ({
      width: 800,
      height: 600,
      top: 0,
      left: 0,
      bottom: 600,
      right: 800,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    }));

    mockCallback = jest.fn();
    
    // Mock console methods to reduce noise
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'warn').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Basic functionality', () => {
    test('should initialize without errors', () => {
      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback
        })
      );

      expect(result.current).toBeDefined();
      expect(result.current.dimensions).toEqual({ cols: 0, rows: 0 });
    });

    test('should setup ResizeObserver when container is provided', () => {
      renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback
        })
      );

      expect(ResizeObserver).toHaveBeenCalledWith(expect.any(Function));
      expect(ResizeObserver.prototype.observe).toHaveBeenCalledWith(mockContainer);
    });

    test('should not setup ResizeObserver when container is null', () => {
      renderHook(() => 
        useTerminalResize({
          containerRef: { current: null },
          onResize: mockCallback
        })
      );

      expect(ResizeObserver.prototype.observe).not.toHaveBeenCalled();
    });
  });

  describe('Resize calculations', () => {
    test('should calculate dimensions based on character size', async () => {
      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20
        })
      );

      // Trigger resize
      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 800, height: 600 }
          }]);
        }
      });

      // Wait for async operations
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(result.current.dimensions).toEqual({
        cols: Math.floor(800 / 10), // 80 columns
        rows: Math.floor(600 / 20)  // 30 rows
      });
    });

    test('should use default character dimensions', async () => {
      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 800, height: 600 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      // Should use default dimensions (8x16 typically)
      expect(result.current.dimensions.cols).toBeGreaterThan(0);
      expect(result.current.dimensions.rows).toBeGreaterThan(0);
    });

    test('should handle minimum dimensions', async () => {
      mockContainer.getBoundingClientRect = jest.fn(() => ({
        width: 50,
        height: 30,
        top: 0,
        left: 0,
        bottom: 30,
        right: 50,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      }));

      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20,
          minCols: 20,
          minRows: 5
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 50, height: 30 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(result.current.dimensions).toEqual({
        cols: 20, // Should use minimum
        rows: 5   // Should use minimum
      });
    });

    test('should handle maximum dimensions', async () => {
      mockContainer.getBoundingClientRect = jest.fn(() => ({
        width: 2000,
        height: 1500,
        top: 0,
        left: 0,
        bottom: 1500,
        right: 2000,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      }));

      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20,
          maxCols: 100,
          maxRows: 50
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 2000, height: 1500 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(result.current.dimensions).toEqual({
        cols: 100, // Should use maximum
        rows: 50   // Should use maximum
      });
    });
  });

  describe('Callback behavior', () => {
    test('should call onResize callback when dimensions change', async () => {
      renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 800, height: 600 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(mockCallback).toHaveBeenCalledWith({
        cols: 80,
        rows: 30
      });
    });

    test('should not call callback if dimensions have not changed', async () => {
      const { rerender } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20
        })
      );

      // First resize
      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 800, height: 600 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(mockCallback).toHaveBeenCalledTimes(1);

      // Second resize with same dimensions
      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 800, height: 600 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(mockCallback).toHaveBeenCalledTimes(1); // Should not be called again
    });

    test('should work without onResize callback', async () => {
      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          charWidth: 10,
          charHeight: 20
        })
      );

      expect(() => {
        act(() => {
          const callback = (mockContainer as any).__resizeCallback;
          if (callback) {
            callback([{
              target: mockContainer,
              contentRect: { width: 800, height: 600 }
            }]);
          }
        });
      }).not.toThrow();

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(result.current.dimensions).toEqual({ cols: 80, rows: 30 });
    });
  });

  describe('Debouncing', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    test('should debounce rapid resize events', async () => {
      renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20,
          debounceMs: 100
        })
      );

      // Trigger multiple rapid resizes
      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        for (let i = 0; i < 5; i++) {
          if (callback) {
            callback([{
              target: mockContainer,
              contentRect: { width: 800 + i * 10, height: 600 }
            }]);
          }
        }
      });

      // Callback should not be called yet
      expect(mockCallback).not.toHaveBeenCalled();

      // Fast-forward time
      act(() => {
        jest.advanceTimersByTime(100);
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      // Should be called only once with the last dimensions
      expect(mockCallback).toHaveBeenCalledTimes(1);
    });

    test('should handle custom debounce timing', async () => {
      renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20,
          debounceMs: 200
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 800, height: 600 }
          }]);
        }
      });

      // Should not be called after 100ms
      act(() => {
        jest.advanceTimersByTime(100);
      });
      expect(mockCallback).not.toHaveBeenCalled();

      // Should be called after 200ms
      act(() => {
        jest.advanceTimersByTime(100);
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(mockCallback).toHaveBeenCalledTimes(1);
    });
  });

  describe('Cleanup', () => {
    test('should cleanup ResizeObserver on unmount', () => {
      const { unmount } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback
        })
      );

      unmount();

      expect(ResizeObserver.prototype.disconnect).toHaveBeenCalled();
    });

    test('should cleanup when container changes', () => {
      const { rerender } = renderHook(({ containerRef }) => 
        useTerminalResize({
          containerRef,
          onResize: mockCallback
        }), {
        initialProps: { containerRef: { current: mockContainer } }
      });

      // Change container
      const newContainer = document.createElement('div');
      rerender({ containerRef: { current: newContainer } });

      expect(ResizeObserver.prototype.disconnect).toHaveBeenCalled();
    });
  });

  describe('Edge cases', () => {
    test('should handle zero dimensions gracefully', async () => {
      mockContainer.getBoundingClientRect = jest.fn(() => ({
        width: 0,
        height: 0,
        top: 0,
        left: 0,
        bottom: 0,
        right: 0,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      }));

      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 0, height: 0 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(result.current.dimensions).toEqual({ cols: 0, rows: 0 });
    });

    test('should handle fractional dimensions', async () => {
      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 7.5, // Fractional character width
          charHeight: 15.3 // Fractional character height
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 800, height: 600 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      // Should floor the results
      expect(result.current.dimensions).toEqual({
        cols: Math.floor(800 / 7.5),
        rows: Math.floor(600 / 15.3)
      });
    });

    test('should handle very large dimensions', async () => {
      mockContainer.getBoundingClientRect = jest.fn(() => ({
        width: 10000,
        height: 8000,
        top: 0,
        left: 0,
        bottom: 8000,
        right: 10000,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      }));

      const { result } = renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 1,
          charHeight: 1
        })
      );

      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        if (callback) {
          callback([{
            target: mockContainer,
            contentRect: { width: 10000, height: 8000 }
          }]);
        }
      });

      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      expect(result.current.dimensions).toEqual({
        cols: 10000,
        rows: 8000
      });
    });

    test('should handle ResizeObserver not supported', () => {
      const originalResizeObserver = global.ResizeObserver;
      delete (global as any).ResizeObserver;

      expect(() => {
        renderHook(() => 
          useTerminalResize({
            containerRef: { current: mockContainer },
            onResize: mockCallback
          })
        );
      }).not.toThrow();

      global.ResizeObserver = originalResizeObserver;
    });
  });

  describe('Performance', () => {
    test('should handle many rapid resize events efficiently', async () => {
      const startTime = performance.now();

      renderHook(() => 
        useTerminalResize({
          containerRef: { current: mockContainer },
          onResize: mockCallback,
          charWidth: 10,
          charHeight: 20,
          debounceMs: 50
        })
      );

      // Trigger many resize events
      act(() => {
        const callback = (mockContainer as any).__resizeCallback;
        for (let i = 0; i < 100; i++) {
          if (callback) {
            callback([{
              target: mockContainer,
              contentRect: { width: 800 + i, height: 600 }
            }]);
          }
        }
      });

      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(100); // Should be fast
    });

    test('should not cause memory leaks on multiple mounts/unmounts', () => {
      for (let i = 0; i < 10; i++) {
        const { unmount } = renderHook(() => 
          useTerminalResize({
            containerRef: { current: mockContainer },
            onResize: mockCallback
          })
        );
        unmount();
      }

      // Should not throw or cause issues
      expect(ResizeObserver.prototype.disconnect).toHaveBeenCalledTimes(10);
    });
  });
});

// Create the missing hook if it doesn't exist
// This is a basic implementation based on common terminal resize patterns
export function useTerminalResize({
  containerRef,
  onResize,
  charWidth = 8,
  charHeight = 16,
  minCols = 0,
  minRows = 0,
  maxCols = Infinity,
  maxRows = Infinity,
  debounceMs = 16
}: {
  containerRef: React.RefObject<HTMLElement>;
  onResize?: (dimensions: { cols: number; rows: number }) => void;
  charWidth?: number;
  charHeight?: number;
  minCols?: number;
  minRows?: number;
  maxCols?: number;
  maxRows?: number;
  debounceMs?: number;
}) {
  const [dimensions, setDimensions] = React.useState({ cols: 0, rows: 0 });
  const debounceTimer = React.useRef<NodeJS.Timeout>();

  const calculateDimensions = React.useCallback((width: number, height: number) => {
    const cols = Math.max(minCols, Math.min(maxCols, Math.floor(width / charWidth)));
    const rows = Math.max(minRows, Math.min(maxRows, Math.floor(height / charHeight)));
    return { cols, rows };
  }, [charWidth, charHeight, minCols, minRows, maxCols, maxRows]);

  React.useEffect(() => {
    if (!containerRef.current || typeof ResizeObserver === 'undefined') {
      return;
    }

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;

      const { width, height } = entry.contentRect;
      const newDimensions = calculateDimensions(width, height);

      // Debounce the update
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }

      debounceTimer.current = setTimeout(() => {
        setDimensions(prevDimensions => {
          if (prevDimensions.cols !== newDimensions.cols || prevDimensions.rows !== newDimensions.rows) {
            onResize?.(newDimensions);
            return newDimensions;
          }
          return prevDimensions;
        });
      }, debounceMs);
    });

    observer.observe(containerRef.current);

    return () => {
      observer.disconnect();
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }
    };
  }, [containerRef, calculateDimensions, onResize, debounceMs]);

  return { dimensions };
}

// Add React import if not available
import * as React from 'react';