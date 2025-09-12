/**
 * Comprehensive unit tests for useTerminalResize hook
 * Tests all resize functionality with ResizeObserver mocking and edge cases
 */

import { renderHook, act } from '@testing-library/react';
import { useTerminalResize } from '../useTerminalResize';

// Mock ResizeObserver
const mockObserve = jest.fn();
const mockDisconnect = jest.fn();
const mockUnobserve = jest.fn();

global.ResizeObserver = jest.fn().mockImplementation((callback) => {
  return {
    observe: mockObserve,
    disconnect: mockDisconnect,
    unobserve: mockUnobserve,
    callback,
  };
});

// Mock console methods
const mockConsole = {
  warn: jest.spyOn(console, 'warn').mockImplementation(),
  error: jest.spyOn(console, 'error').mockImplementation(),
};

// Helper to create mock terminal
const createMockTerminal = (cols = 80, rows = 24) => ({
  cols,
  rows,
  resize: jest.fn(),
});

// Helper to create mock container
const createMockContainer = (width = 800, height = 600) => {
  const container = document.createElement('div');
  Object.defineProperty(container, 'getBoundingClientRect', {
    value: jest.fn(() => ({
      width,
      height,
      top: 0,
      left: 0,
      right: width,
      bottom: height,
    })),
  });
  return container;
};

describe('useTerminalResize Hook - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    mockConsole.warn.mockClear();
    mockConsole.error.mockClear();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  afterAll(() => {
    mockConsole.warn.mockRestore();
    mockConsole.error.mockRestore();
  });

  describe('Basic Functionality', () => {
    it('should initialize with default dimensions', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer();

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container)
      );

      expect(result.current.dimensions.cols).toBe(80);
      expect(result.current.dimensions.rows).toBe(24);
      expect(result.current.dimensions.width).toBe(800);
      expect(result.current.dimensions.height).toBe(600);
    });

    it('should setup ResizeObserver on mount', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer();

      renderHook(() => useTerminalResize(terminal, container));

      expect(global.ResizeObserver).toHaveBeenCalled();
      expect(mockObserve).toHaveBeenCalledWith(container);
    });

    it('should cleanup ResizeObserver on unmount', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer();

      const { unmount } = renderHook(() =>
        useTerminalResize(terminal, container)
      );

      unmount();

      expect(mockDisconnect).toHaveBeenCalled();
    });
  });

  describe('Dimension Calculation', () => {
    it('should calculate dimensions based on character size', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(1600, 480); // 1600/8 = 200 cols, 480/16 = 30 rows

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          charWidth: 8,
          charHeight: 16,
        })
      );

      expect(result.current.dimensions.cols).toBe(200);
      expect(result.current.dimensions.rows).toBe(30);
    });

    it('should apply padding constraints', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          charWidth: 8,
          charHeight: 16,
          padding: { top: 20, bottom: 20, left: 40, right: 40 },
        })
      );

      // Available space: 800 - 80 = 720, 600 - 40 = 560
      expect(result.current.dimensions.cols).toBe(90); // 720/8
      expect(result.current.dimensions.rows).toBe(35); // 560/16
    });

    it('should apply minimum constraints', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(40, 32); // Very small container

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          charWidth: 8,
          charHeight: 16,
          minCols: 10,
          minRows: 5,
        })
      );

      expect(result.current.dimensions.cols).toBe(10);
      expect(result.current.dimensions.rows).toBe(5);
    });

    it('should apply maximum constraints', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(2000, 1000); // Very large container

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          charWidth: 8,
          charHeight: 16,
          maxCols: 100,
          maxRows: 50,
        })
      );

      expect(result.current.dimensions.cols).toBe(100);
      expect(result.current.dimensions.rows).toBe(50);
    });

    it('should apply aspect ratio constraints', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(1600, 800);

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          charWidth: 8,
          charHeight: 16,
          aspectRatio: 2.0, // 2:1 ratio
        })
      );

      // 1600/8 = 200 cols, 800/16 = 50 rows
      // Ratio would be 200/50 = 4.0, which is > 2.0
      // So cols should be reduced to match ratio: 50 * 2.0 = 100
      expect(result.current.dimensions.cols).toBe(100);
      expect(result.current.dimensions.rows).toBe(50);
    });
  });

  describe('Responsive Breakpoints', () => {
    it('should apply mobile breakpoint', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(400, 600); // Mobile width

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          responsive: {
            mobile: { maxWidth: 768, cols: 40, rows: 20 },
          },
        })
      );

      expect(result.current.dimensions.cols).toBe(40);
      expect(result.current.dimensions.rows).toBe(20);
    });

    it('should apply tablet breakpoint', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600); // Tablet width

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          responsive: {
            mobile: { maxWidth: 480, cols: 30, rows: 15 },
            tablet: { maxWidth: 1024, cols: 60, rows: 30 },
          },
        })
      );

      expect(result.current.dimensions.cols).toBe(60);
      expect(result.current.dimensions.rows).toBe(30);
    });

    it('should apply desktop breakpoint', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(1200, 800); // Desktop width

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          responsive: {
            mobile: { maxWidth: 480, cols: 30, rows: 15 },
            tablet: { maxWidth: 1024, cols: 60, rows: 30 },
            desktop: { minWidth: 1200, cols: 100, rows: 40 },
          },
        })
      );

      expect(result.current.dimensions.cols).toBe(100);
      expect(result.current.dimensions.rows).toBe(40);
    });
  });

  describe('ResizeObserver Integration', () => {
    it('should handle resize events', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      renderHook(() => useTerminalResize(terminal, container));

      // Get the callback passed to ResizeObserver
      const ResizeObserverConstructor = global.ResizeObserver as jest.MockedClass<typeof ResizeObserver>;
      const callback = ResizeObserverConstructor.mock.calls[0][0];

      // Simulate resize event
      const mockEntry = {
        contentRect: { width: 1000, height: 800 },
      };

      act(() => {
        callback([mockEntry] as any);
      });

      expect(terminal.resize).toHaveBeenCalledWith(125, 50); // 1000/8, 800/16
    });

    it('should debounce resize events', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      renderHook(() =>
        useTerminalResize(terminal, container, { debounceMs: 100 })
      );

      const ResizeObserverConstructor = global.ResizeObserver as jest.MockedClass<typeof ResizeObserver>;
      const callback = ResizeObserverConstructor.mock.calls[0][0];

      const mockEntry = {
        contentRect: { width: 1000, height: 800 },
      };

      // Trigger multiple resize events
      act(() => {
        callback([mockEntry] as any);
        callback([mockEntry] as any);
        callback([mockEntry] as any);
      });

      // Should not have called resize yet
      expect(terminal.resize).not.toHaveBeenCalled();

      // Advance timers
      act(() => {
        jest.advanceTimersByTime(100);
      });

      // Should now have called resize once
      expect(terminal.resize).toHaveBeenCalledTimes(1);
    });

    it('should skip updates for unchanged dimensions', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      renderHook(() => useTerminalResize(terminal, container));

      const ResizeObserverConstructor = global.ResizeObserver as jest.MockedClass<typeof ResizeObserver>;
      const callback = ResizeObserverConstructor.mock.calls[0][0];

      const mockEntry = {
        contentRect: { width: 800, height: 600 }, // Same dimensions
      };

      // Clear initial resize call
      terminal.resize.mockClear();

      act(() => {
        callback([mockEntry] as any);
      });

      expect(terminal.resize).not.toHaveBeenCalled();
    });

    it('should handle empty entries array', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      renderHook(() => useTerminalResize(terminal, container));

      const ResizeObserverConstructor = global.ResizeObserver as jest.MockedClass<typeof ResizeObserver>;
      const callback = ResizeObserverConstructor.mock.calls[0][0];

      act(() => {
        callback([]);
      });

      // Should not crash or call terminal resize
      expect(terminal.resize).toHaveBeenCalledTimes(1); // Only initial call
    });
  });

  describe('Terminal Resize Integration', () => {
    it('should call terminal resize method', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(1000, 800);

      renderHook(() => useTerminalResize(terminal, container));

      expect(terminal.resize).toHaveBeenCalledWith(125, 50);
    });

    it('should handle terminal resize errors', () => {
      const terminal = createMockTerminal();
      terminal.resize.mockImplementation(() => {
        throw new Error('Resize failed');
      });
      const container = createMockContainer(1000, 800);

      renderHook(() => useTerminalResize(terminal, container));

      expect(mockConsole.error).toHaveBeenCalledWith(
        'Terminal resize failed:',
        expect.any(Error)
      );
    });

    it('should work without terminal resize method', () => {
      const terminal = { cols: 80, rows: 24 }; // No resize method
      const container = createMockContainer(1000, 800);

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container)
      );

      expect(result.current.dimensions.cols).toBe(125);
      expect(result.current.dimensions.rows).toBe(50);
    });
  });

  describe('Dimension Change Callback', () => {
    it('should call onDimensionChange callback', () => {
      const onDimensionChange = jest.fn();
      const terminal = createMockTerminal();
      const container = createMockContainer(1000, 800);

      renderHook(() =>
        useTerminalResize(terminal, container, { onDimensionChange })
      );

      expect(onDimensionChange).toHaveBeenCalledWith({
        cols: 125,
        rows: 50,
        width: 1000,
        height: 800,
      });
    });

    it('should call callback on resize events', () => {
      const onDimensionChange = jest.fn();
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      renderHook(() =>
        useTerminalResize(terminal, container, { onDimensionChange })
      );

      const ResizeObserverConstructor = global.ResizeObserver as jest.MockedClass<typeof ResizeObserver>;
      const callback = ResizeObserverConstructor.mock.calls[0][0];

      onDimensionChange.mockClear();

      const mockEntry = {
        contentRect: { width: 1000, height: 800 },
      };

      act(() => {
        callback([mockEntry] as any);
      });

      expect(onDimensionChange).toHaveBeenCalledWith({
        cols: 125,
        rows: 50,
        width: 1000,
        height: 800,
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle null terminal', () => {
      const container = createMockContainer(800, 600);

      const { result } = renderHook(() =>
        useTerminalResize(null, container)
      );

      expect(result.current.dimensions.cols).toBe(100); // 800/8
      expect(result.current.dimensions.rows).toBe(37); // 600/16 (rounded down)
    });

    it('should handle null container', () => {
      const terminal = createMockTerminal();

      const { result } = renderHook(() =>
        useTerminalResize(terminal, null)
      );

      expect(result.current.dimensions.cols).toBe(80); // Terminal default
      expect(result.current.dimensions.rows).toBe(24); // Terminal default
    });

    it('should handle ResizeObserver not available', () => {
      // Temporarily remove ResizeObserver
      const originalResizeObserver = global.ResizeObserver;
      delete (global as any).ResizeObserver;

      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      renderHook(() => useTerminalResize(terminal, container));

      expect(mockConsole.warn).toHaveBeenCalledWith(
        'ResizeObserver not available'
      );

      // Restore ResizeObserver
      global.ResizeObserver = originalResizeObserver;
    });

    it('should handle ResizeObserver creation errors', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      // Mock ResizeObserver to throw
      const originalResizeObserver = global.ResizeObserver;
      global.ResizeObserver = jest.fn().mockImplementation(() => {
        throw new Error('ResizeObserver creation failed');
      });

      renderHook(() => useTerminalResize(terminal, container));

      expect(mockConsole.warn).toHaveBeenCalledWith(
        'Failed to setup ResizeObserver:',
        expect.any(Error)
      );

      global.ResizeObserver = originalResizeObserver;
    });

    it('should handle container dimension calculation errors', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      // Mock getBoundingClientRect to throw
      container.getBoundingClientRect = jest.fn().mockImplementation(() => {
        throw new Error('getBoundingClientRect failed');
      });

      renderHook(() => useTerminalResize(terminal, container));

      expect(mockConsole.warn).toHaveBeenCalledWith(
        'Error calculating container dimensions:',
        expect.any(Error)
      );
    });

    it('should handle negative dimensions', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          padding: { top: 400, bottom: 400, left: 500, right: 500 }, // Excessive padding
        })
      );

      // Should still have minimum dimensions
      expect(result.current.dimensions.cols).toBeGreaterThanOrEqual(1);
      expect(result.current.dimensions.rows).toBeGreaterThanOrEqual(1);
    });

    it('should handle zero character dimensions', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      const { result } = renderHook(() =>
        useTerminalResize(terminal, container, {
          charWidth: 0,
          charHeight: 0,
        })
      );

      // Should handle gracefully (likely infinite or very large numbers)
      expect(result.current.dimensions.cols).toBeDefined();
      expect(result.current.dimensions.rows).toBeDefined();
    });
  });

  describe('Cleanup and Memory Management', () => {
    it('should clear debounce timeout on unmount', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      const { unmount } = renderHook(() =>
        useTerminalResize(terminal, container, { debounceMs: 100 })
      );

      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
    });

    it('should handle multiple unmounts gracefully', () => {
      const terminal = createMockTerminal();
      const container = createMockContainer(800, 600);

      const { unmount } = renderHook(() =>
        useTerminalResize(terminal, container)
      );

      // Should not throw on multiple unmounts
      expect(() => {
        unmount();
        unmount();
      }).not.toThrow();
    });
  });
});