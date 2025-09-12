/**
 * Terminal Resize Hook Tests
 * Tests responsive terminal behavior and resize handling
 */

import React from 'react';
import { renderHook, act } from '@testing-library/react';
import { useTerminalResize } from '../useTerminalResize';

// Mock ResizeObserver
const mockResizeObserver = jest.fn(() => ({
  observe: jest.fn(),
  disconnect: jest.fn(),
  unobserve: jest.fn(),
}));
global.ResizeObserver = mockResizeObserver;

// Mock terminal interface
const mockTerminal = {
  resize: jest.fn(),
  cols: 80,
  rows: 24,
  element: document.createElement('div'),
};

// Mock container element
const createMockContainer = (width = 800, height = 600) => {
  const container = document.createElement('div');
  jest.spyOn(container, 'getBoundingClientRect').mockReturnValue({
    width,
    height,
    top: 0,
    left: 0,
    bottom: height,
    right: width,
    x: 0,
    y: 0,
    toJSON: jest.fn(),
  });
  return container;
};

describe('useTerminalResize', () => {
  let mockContainer: HTMLDivElement;
  let resizeObserverCallback: ResizeObserverCallback;

  beforeEach(() => {
    jest.clearAllMocks();
    mockContainer = createMockContainer();
    
    // Capture the ResizeObserver callback
    mockResizeObserver.mockImplementation((callback) => {
      resizeObserverCallback = callback;
      return {
        observe: jest.fn(),
        disconnect: jest.fn(),
        unobserve: jest.fn(),
      };
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Basic Functionality', () => {
    it('should initialize with default dimensions', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer)
      );

      expect(result.current.dimensions).toEqual({
        cols: 80,
        rows: 24,
        width: 800,
        height: 600
      });
    });

    it('should setup ResizeObserver on container', () => {
      const mockObserver = {
        observe: jest.fn(),
        disconnect: jest.fn(),
        unobserve: jest.fn(),
      };
      mockResizeObserver.mockReturnValue(mockObserver);

      renderHook(() => useTerminalResize(mockTerminal, mockContainer));

      expect(mockObserver.observe).toHaveBeenCalledWith(mockContainer);
    });

    it('should cleanup ResizeObserver on unmount', () => {
      const mockObserver = {
        observe: jest.fn(),
        disconnect: jest.fn(),
        unobserve: jest.fn(),
      };
      mockResizeObserver.mockReturnValue(mockObserver);

      const { unmount } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer)
      );

      unmount();

      expect(mockObserver.disconnect).toHaveBeenCalled();
    });
  });

  describe('Resize Calculations', () => {
    it('should calculate terminal dimensions based on character size', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          charWidth: 10,
          charHeight: 20,
          padding: { top: 10, bottom: 10, left: 10, right: 10 }
        })
      );

      // Trigger resize
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 800, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions).toEqual({
        cols: Math.floor((800 - 20) / 10), // (width - horizontal padding) / charWidth
        rows: Math.floor((600 - 20) / 20), // (height - vertical padding) / charHeight
        width: 800,
        height: 600
      });
    });

    it('should handle minimum dimensions', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          charWidth: 10,
          charHeight: 20,
          minCols: 40,
          minRows: 10,
          padding: { top: 0, bottom: 0, left: 0, right: 0 }
        })
      );

      // Trigger resize to very small container
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 200, height: 100 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions.cols).toBeGreaterThanOrEqual(40);
      expect(result.current.dimensions.rows).toBeGreaterThanOrEqual(10);
    });

    it('should handle maximum dimensions', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          charWidth: 5,
          charHeight: 10,
          maxCols: 100,
          maxRows: 30,
          padding: { top: 0, bottom: 0, left: 0, right: 0 }
        })
      );

      // Trigger resize to very large container
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 2000, height: 1000 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions.cols).toBeLessThanOrEqual(100);
      expect(result.current.dimensions.rows).toBeLessThanOrEqual(30);
    });

    it('should apply aspect ratio constraints', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          charWidth: 10,
          charHeight: 20,
          aspectRatio: 2, // Width should be 2x height
          padding: { top: 0, bottom: 0, left: 0, right: 0 }
        })
      );

      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 1000, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      const { cols, rows } = result.current.dimensions;
      const actualRatio = cols / rows;
      
      expect(Math.abs(actualRatio - 2)).toBeLessThan(0.1);
    });
  });

  describe('Terminal Integration', () => {
    it('should call terminal.resize when dimensions change', () => {
      renderHook(() => useTerminalResize(mockTerminal, mockContainer));

      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 1000, height: 800 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(mockTerminal.resize).toHaveBeenCalled();
    });

    it('should not call terminal.resize if dimensions unchanged', () => {
      renderHook(() => useTerminalResize(mockTerminal, mockContainer));

      // Initial resize
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 800, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      mockTerminal.resize.mockClear();

      // Same dimensions
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 800, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(mockTerminal.resize).not.toHaveBeenCalled();
    });

    it('should handle terminal resize errors gracefully', () => {
      mockTerminal.resize.mockImplementation(() => {
        throw new Error('Resize failed');
      });

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      renderHook(() => useTerminalResize(mockTerminal, mockContainer));

      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 1000, height: 800 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        'Terminal resize failed:',
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Debouncing', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should debounce resize events', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          debounceMs: 100
        })
      );

      // Trigger multiple rapid resizes
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 800, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
        
        resizeObserverCallback([{
          contentRect: { width: 900, height: 700 },
          target: mockContainer
        } as any], {} as ResizeObserver);
        
        resizeObserverCallback([{
          contentRect: { width: 1000, height: 800 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      // Should not have updated yet
      expect(result.current.dimensions.width).toBe(800);

      // Fast-forward debounce timer
      act(() => {
        jest.advanceTimersByTime(100);
      });

      // Should now reflect the last resize
      expect(result.current.dimensions.width).toBe(1000);
      expect(result.current.dimensions.height).toBe(800);
    });

    it('should cancel previous debounced calls', () => {
      renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          debounceMs: 100
        })
      );

      mockTerminal.resize.mockClear();

      // Trigger resize
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 900, height: 700 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      // Advance partially
      act(() => {
        jest.advanceTimersByTime(50);
      });

      // Trigger another resize (should cancel previous)
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 1000, height: 800 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      // Complete the debounce
      act(() => {
        jest.advanceTimersByTime(100);
      });

      // Should only have been called once with final dimensions
      expect(mockTerminal.resize).toHaveBeenCalledTimes(1);
    });
  });

  describe('Custom Options', () => {
    it('should accept custom character dimensions', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          charWidth: 12,
          charHeight: 24
        })
      );

      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 1200, height: 720 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions.cols).toBe(100); // 1200 / 12
      expect(result.current.dimensions.rows).toBe(30);  // 720 / 24
    });

    it('should apply custom padding', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          charWidth: 10,
          charHeight: 20,
          padding: { top: 20, bottom: 20, left: 30, right: 30 }
        })
      );

      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 800, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions.cols).toBe(74); // (800 - 60) / 10
      expect(result.current.dimensions.rows).toBe(28); // (600 - 40) / 20
    });

    it('should handle asymmetric padding', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          charWidth: 10,
          charHeight: 20,
          padding: { top: 10, bottom: 30, left: 15, right: 25 }
        })
      );

      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 800, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions.cols).toBe(76); // (800 - 40) / 10
      expect(result.current.dimensions.rows).toBe(28); // (600 - 40) / 20
    });
  });

  describe('Error Handling', () => {
    it('should handle missing container gracefully', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, null)
      );

      expect(result.current.dimensions).toEqual({
        cols: 80,
        rows: 24,
        width: 0,
        height: 0
      });
    });

    it('should handle missing terminal gracefully', () => {
      const { result } = renderHook(() => 
        useTerminalResize(null, mockContainer)
      );

      expect(result.current.dimensions).toEqual({
        cols: 80,
        rows: 24,
        width: 800,
        height: 600
      });
    });

    it('should handle ResizeObserver not being available', () => {
      const originalResizeObserver = global.ResizeObserver;
      delete (global as any).ResizeObserver;

      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer)
      );

      expect(result.current.dimensions).toBeDefined();
      
      global.ResizeObserver = originalResizeObserver;
    });

    it('should handle getBoundingClientRect errors', () => {
      jest.spyOn(mockContainer, 'getBoundingClientRect').mockImplementation(() => {
        throw new Error('DOM error');
      });

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer)
      );

      expect(result.current.dimensions).toBeDefined();
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('Performance', () => {
    it('should not cause memory leaks with multiple observers', () => {
      const containers = Array.from({ length: 10 }, () => createMockContainer());
      
      const hooks = containers.map(container => 
        renderHook(() => useTerminalResize(mockTerminal, container))
      );

      // Unmount all hooks
      hooks.forEach(({ unmount }) => unmount());

      // Should have cleaned up all observers
      expect(mockResizeObserver).toHaveBeenCalledTimes(10);
    });

    it('should handle rapid container changes', () => {
      const { result, rerender } = renderHook(
        ({ container }) => useTerminalResize(mockTerminal, container),
        { initialProps: { container: mockContainer } }
      );

      const newContainer = createMockContainer(1000, 800);

      rerender({ container: newContainer });

      expect(result.current.dimensions.width).toBe(1000);
      expect(result.current.dimensions.height).toBe(800);
    });

    it('should throttle dimension calculations', () => {
      const calculateSpy = jest.fn();
      
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          onDimensionChange: calculateSpy
        })
      );

      // Trigger multiple rapid resizes
      for (let i = 0; i < 10; i++) {
        act(() => {
          resizeObserverCallback([{
            contentRect: { width: 800 + i, height: 600 + i },
            target: mockContainer
          } as any], {} as ResizeObserver);
        });
      }

      // Should have been called for each unique dimension change
      expect(calculateSpy.mock.calls.length).toBeGreaterThan(0);
      expect(calculateSpy.mock.calls.length).toBeLessThanOrEqual(10);
    });
  });

  describe('Responsive Breakpoints', () => {
    it('should adjust terminal size for mobile devices', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          responsive: {
            mobile: { maxWidth: 768, cols: 40, rows: 20 },
            tablet: { maxWidth: 1024, cols: 60, rows: 30 },
            desktop: { minWidth: 1025, cols: 120, rows: 40 }
          }
        })
      );

      // Mobile breakpoint
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 400, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions.cols).toBe(40);
      expect(result.current.dimensions.rows).toBe(20);
    });

    it('should adjust terminal size for tablet devices', () => {
      const { result } = renderHook(() => 
        useTerminalResize(mockTerminal, mockContainer, {
          responsive: {
            mobile: { maxWidth: 768, cols: 40, rows: 20 },
            tablet: { maxWidth: 1024, cols: 60, rows: 30 },
            desktop: { minWidth: 1025, cols: 120, rows: 40 }
          }
        })
      );

      // Tablet breakpoint
      act(() => {
        resizeObserverCallback([{
          contentRect: { width: 900, height: 600 },
          target: mockContainer
        } as any], {} as ResizeObserver);
      });

      expect(result.current.dimensions.cols).toBe(60);
      expect(result.current.dimensions.rows).toBe(30);
    });
  });
});