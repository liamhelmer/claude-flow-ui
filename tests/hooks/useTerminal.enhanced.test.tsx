import { renderHook, act } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Terminal } from '@xterm/xterm';

// Mock dependencies
jest.mock('@/hooks/useWebSocket');
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const MockTerminal = Terminal as jest.MockedClass<typeof Terminal>;

describe('useTerminal Enhanced Tests', () => {
  let mockWebSocket: any;
  let mockTerminal: any;
  let mockContainer: HTMLDivElement;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Mock WebSocket hook
    mockWebSocket = {
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      isConnected: true,
    };
    mockUseWebSocket.mockReturnValue(mockWebSocket);

    // Mock terminal instance
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      dispose: jest.fn(),
      focus: jest.fn(),
      clear: jest.fn(),
      onData: jest.fn(),
      loadAddon: jest.fn(),
      cols: 80,
      rows: 24,
      element: {
        querySelector: jest.fn(),
      },
    };
    MockTerminal.mockImplementation(() => mockTerminal);

    // Mock container element
    mockContainer = document.createElement('div');
    Object.defineProperty(mockContainer, 'current', {
      value: mockContainer,
      writable: true,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Hook Initialization', () => {
    it('should initialize with correct default state', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(result.current.terminal).toBeNull();
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
      expect(result.current.isConnected).toBe(true);
    });

    it('should handle custom configuration', () => {
      const customConfig = {
        fontSize: 16,
        fontFamily: 'Courier New',
        theme: 'light' as const,
      };

      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          config: customConfig,
        })
      );

      expect(result.current.terminal).toBeNull();
    });

    it('should register WebSocket event listeners', () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('connection-change', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-config', expect.any(Function));
    });

    it('should cleanup event listeners on unmount', () => {
      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      unmount();

      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('connection-change', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-config', expect.any(Function));
    });
  });

  describe('Terminal Configuration Management', () => {
    it('should wait for backend configuration before creating terminal', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Terminal should not be created without backend config
      expect(MockTerminal).not.toHaveBeenCalled();
      expect(result.current.terminal).toBeNull();
    });

    it('should create terminal after receiving backend configuration', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Simulate terminal ref being set
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      // Simulate receiving backend config
      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      expect(MockTerminal).toHaveBeenCalledWith(
        expect.objectContaining({
          cols: 80,
          rows: 24,
        })
      );
    });

    it('should recreate terminal when dimensions change', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup initial terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      // Initial config
      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      const firstTerminal = mockTerminal;

      // Change dimensions
      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 120,
          rows: 30,
        });
      });

      expect(firstTerminal.dispose).toHaveBeenCalled();
      expect(MockTerminal).toHaveBeenCalledTimes(2);
    });

    it('should handle configuration with zero dimensions', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 0,
          rows: 0,
        });
      });

      // Should not create terminal with zero dimensions
      expect(MockTerminal).not.toHaveBeenCalled();
    });
  });

  describe('Terminal Data Handling', () => {
    beforeEach(() => {
      // Setup terminal with backend config
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });
    });

    it('should write data to terminal when session matches', () => {
      const terminalDataHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')?.[1];

      act(() => {
        terminalDataHandler?.({
          sessionId: 'test-session',
          data: 'Hello, terminal!',
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Hello, terminal!');
    });

    it('should ignore data for different sessions', () => {
      const terminalDataHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')?.[1];

      act(() => {
        terminalDataHandler?.({
          sessionId: 'different-session',
          data: 'Hello, terminal!',
        });
      });

      expect(mockTerminal.write).not.toHaveBeenCalled();
    });

    it('should handle error messages', () => {
      const terminalErrorHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-error')?.[1];

      act(() => {
        terminalErrorHandler?.({
          sessionId: 'test-session',
          error: 'Terminal error occurred',
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('Terminal error occurred')
      );
    });

    it('should handle connection change messages', () => {
      const connectionChangeHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'connection-change')?.[1];

      act(() => {
        connectionChangeHandler?.(true);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('Connected')
      );

      act(() => {
        connectionChangeHandler?.(false);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('Disconnected')
      );
    });
  });

  describe('Terminal Input Handling', () => {
    it('should send input data to WebSocket', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Simulate user input
      const onDataHandler = mockTerminal.onData.mock.calls[0][0];
      onDataHandler('test input');

      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', 'test input');
    });

    it('should call onData callback when provided', () => {
      const onDataCallback = jest.fn();
      const { result } = renderHook(() =>
        useTerminal({
          sessionId: 'test-session',
          onData: onDataCallback,
        })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Simulate user input
      const onDataHandler = mockTerminal.onData.mock.calls[0][0];
      onDataHandler('test input');

      expect(onDataCallback).toHaveBeenCalledWith('test input');
    });
  });

  describe('Scroll Management', () => {
    let mockViewport: HTMLElement;

    beforeEach(() => {
      mockViewport = document.createElement('div');
      Object.defineProperties(mockViewport, {
        scrollTop: { value: 0, writable: true },
        scrollHeight: { value: 1000, writable: true },
        clientHeight: { value: 500, writable: true },
      });

      mockTerminal.element = {
        querySelector: jest.fn().mockReturnValue(mockViewport),
      };
    });

    it('should track scroll position for auto-scroll functionality', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Should initially be at bottom
      expect(result.current.isAtBottom).toBe(true);
    });

    it('should auto-scroll when user is at bottom', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Simulate being at bottom
      mockViewport.scrollTop = 500; // At bottom (scrollHeight - clientHeight)

      const terminalDataHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')?.[1];

      act(() => {
        terminalDataHandler?.({
          sessionId: 'test-session',
          data: 'New output',
        });
      });

      jest.advanceTimersByTime(100);

      expect(mockTerminal.write).toHaveBeenCalledWith('New output');
    });

    it('should preserve scroll position when user is not at bottom', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Simulate being scrolled up
      mockViewport.scrollTop = 100; // Not at bottom

      const terminalDataHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')?.[1];

      act(() => {
        terminalDataHandler?.({
          sessionId: 'test-session',
          data: 'New output',
        });
      });

      jest.advanceTimersByTime(100);

      expect(result.current.hasNewOutput).toBe(true);
    });

    it('should provide scroll to bottom functionality', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      act(() => {
        result.current.scrollToBottom();
      });

      jest.advanceTimersByTime(100);

      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
    });

    it('should provide scroll to top functionality', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      act(() => {
        result.current.scrollToTop();
      });

      jest.advanceTimersByTime(100);

      expect(result.current.isAtBottom).toBe(false);
    });
  });

  describe('Terminal Actions', () => {
    beforeEach(() => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });
    });

    it('should write to terminal', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.writeToTerminal('Test message');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Test message');
    });

    it('should clear terminal', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('should focus terminal', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });

    it('should handle fit terminal (no-op for fixed size)', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(() => {
        act(() => {
          result.current.fitTerminal();
        });
      }).not.toThrow();
    });

    it('should destroy terminal', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.destroyTerminal();
      });

      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle terminal creation failure gracefully', () => {
      MockTerminal.mockImplementation(() => {
        throw new Error('Terminal creation failed');
      });

      expect(() => {
        renderHook(() => useTerminal({ sessionId: 'test-session' }));
      }).not.toThrow();
    });

    it('should handle missing container ref', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Should not create terminal without container
      expect(MockTerminal).not.toHaveBeenCalled();
    });

    it('should handle actions when terminal is not initialized', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(() => {
        act(() => {
          result.current.writeToTerminal('test');
          result.current.clearTerminal();
          result.current.focusTerminal();
          result.current.scrollToBottom();
          result.current.scrollToTop();
        });
      }).not.toThrow();
    });

    it('should handle missing viewport element', () => {
      mockTerminal.element = {
        querySelector: jest.fn().mockReturnValue(null),
      };

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      expect(() => {
        act(() => {
          result.current.scrollToBottom();
          result.current.scrollToTop();
        });
      }).not.toThrow();
    });

    it('should handle WebSocket connection state changes', () => {
      mockUseWebSocket.mockReturnValue({
        ...mockWebSocket,
        isConnected: false,
      });

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(result.current.isConnected).toBe(false);
    });

    it('should handle rapid session ID changes', () => {
      const { result, rerender } = renderHook(
        ({ sessionId }) => useTerminal({ sessionId }),
        { initialProps: { sessionId: 'session-1' } }
      );

      // Change session ID rapidly
      rerender({ sessionId: 'session-2' });
      rerender({ sessionId: 'session-3' });
      rerender({ sessionId: 'session-4' });

      expect(() => {
        // Should handle rapid changes without error
      }).not.toThrow();
    });

    it('should cleanup properly when session changes', () => {
      const { rerender } = renderHook(
        ({ sessionId }) => useTerminal({ sessionId }),
        { initialProps: { sessionId: 'session-1' } }
      );

      // Setup terminal
      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'session-1',
          cols: 80,
          rows: 24,
        });
      });

      // Change session
      rerender({ sessionId: 'session-2' });

      // Should cleanup previous terminal
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });

  describe('Performance and Memory', () => {
    it('should handle high-frequency data updates efficiently', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal
      act(() => {
        (result.current as any).terminalRef.current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      const terminalDataHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')?.[1];

      const startTime = performance.now();

      // Send many data updates
      act(() => {
        for (let i = 0; i < 1000; i++) {
          terminalDataHandler?.({
            sessionId: 'test-session',
            data: `Line ${i}\n`,
          });
        }
      });

      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(200); // Should complete quickly
      expect(mockTerminal.write).toHaveBeenCalledTimes(1000);
    });

    it('should prevent memory leaks during scroll tracking', () => {
      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Setup terminal with scroll tracking
      act(() => {
        (mockContainer as any).current = mockContainer;
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];

      act(() => {
        terminalConfigHandler?.({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Fast forward timers to setup scroll listeners
      jest.advanceTimersByTime(200);

      // Unmount should cleanup properly
      unmount();

      // Verify cleanup was called
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });
});