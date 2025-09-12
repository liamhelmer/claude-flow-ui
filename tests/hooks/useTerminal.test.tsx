import { renderHook, act } from '@testing-library/react';
import { waitFor } from '@testing-library/dom';
import { useTerminal } from '@/hooks/useTerminal';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';

// Mock the xterm.js Terminal and FitAddon
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-fit');
jest.mock('@/hooks/useWebSocket');
jest.mock('@/lib/state/store');

const MockedTerminal = Terminal as jest.MockedClass<typeof Terminal>;
const MockedFitAddon = FitAddon as jest.MockedClass<typeof FitAddon>;

describe('useTerminal', () => {
  let mockTerminal: jest.Mocked<Terminal>;
  let mockFitAddon: jest.Mocked<FitAddon>;
  let mockSendData: jest.Mock;
  let mockResizeTerminal: jest.Mock;
  let mockOn: jest.Mock;
  let mockOff: jest.Mock;

  beforeEach(() => {
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      clear: jest.fn(),
      focus: jest.fn(),
      dispose: jest.fn(),
      onData: jest.fn(),
      onResize: jest.fn(),
      loadAddon: jest.fn(),
      element: {
        querySelector: jest.fn(() => ({
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          scrollTop: 0,
          scrollHeight: 1000,
          clientHeight: 500,
        })),
      },
    } as any;

    mockFitAddon = {
      fit: jest.fn(),
    } as any;

    mockSendData = jest.fn();
    mockResizeTerminal = jest.fn();
    mockOn = jest.fn();
    mockOff = jest.fn();

    MockedTerminal.mockImplementation(() => mockTerminal);
    MockedFitAddon.mockImplementation(() => mockFitAddon);

    // Mock useWebSocket
    const useWebSocket = require('@/hooks/useWebSocket').useWebSocket;
    useWebSocket.mockReturnValue({
      sendData: mockSendData,
      resizeTerminal: mockResizeTerminal,
      on: mockOn,
      off: mockOff,
      isConnected: true,
    });

    // Mock DOM createElement for container ref
    const mockDiv = document.createElement('div');
    Object.defineProperty(mockDiv, 'querySelector', {
      value: jest.fn(() => ({
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        scrollTop: 0,
        scrollHeight: 1000,
        clientHeight: 500,
      })),
    });

    jest.spyOn(document, 'createElement').mockReturnValue(mockDiv);

    // Mock container ref
    Object.defineProperty(document, 'createElement', {
      value: jest.fn(() => mockDiv),
      writable: true,
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.clearAllTimers();
  });

  describe('initialization', () => {
    it('should initialize terminal with correct configuration', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Wait for useEffect to complete
      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      expect(MockedTerminal).toHaveBeenCalledWith(
        expect.objectContaining({
          theme: expect.objectContaining({
            background: '#1e1e1e',
            foreground: '#f0f0f0',
          }),
          fontSize: 14,
          cursorBlink: true,
          scrollback: 999999,
        })
      );
    });

    it('should load FitAddon', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      await waitFor(() => {
        expect(MockedFitAddon).toHaveBeenCalled();
      });

      expect(mockTerminal.loadAddon).toHaveBeenCalledWith(mockFitAddon);
    });

    it('should register event handlers', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      expect(mockTerminal.onResize).toHaveBeenCalled();
      expect(mockOn).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockOn).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockOn).toHaveBeenCalledWith('connection-change', expect.any(Function));
    });

    it('should apply custom config', async () => {
      const customConfig = {
        fontSize: 16,
        fontFamily: 'Custom Font',
        cursorBlink: false,
      };

      renderHook(() =>
        useTerminal({ sessionId: 'test-session', config: customConfig })
      );

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      expect(MockedTerminal).toHaveBeenCalledWith(
        expect.objectContaining({
          fontSize: 16,
          fontFamily: 'Custom Font',
          cursorBlink: false,
        })
      );
    });
  });

  describe('terminal operations', () => {
    it('should write data to terminal', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Wait for terminal to initialize
      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      act(() => {
        result.current.writeToTerminal('test data');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('test data');
    });

    it('should clear terminal', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      act(() => {
        result.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('should focus terminal', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(MockedTerminal).toHaveBeenCalled();
      });

      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });

    it('should fit terminal', async () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(MockedFitAddon).toHaveBeenCalled();
      });

      act(() => {
        result.current.fitTerminal();
      });

      expect(mockFitAddon.fit).toHaveBeenCalled();
    });

    it('should handle fit errors gracefully', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockFitAddon.fit.mockImplementation(() => {
        throw new Error('Fit failed');
      });

      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.fitTerminal();
      });

      expect(consoleSpy).toHaveBeenCalledWith('Failed to fit terminal:', expect.any(Error));
      consoleSpy.mockRestore();
    });
  });

  describe('data handling', () => {
    it('should send data via WebSocket when terminal receives input', () => {
      let onDataCallback: (data: string) => void;
      mockTerminal.onData.mockImplementation((callback) => {
        onDataCallback = callback;
      });

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        onDataCallback!('user input');
      });

      expect(mockSendData).toHaveBeenCalledWith('test-session', 'user input');
    });

    it('should call onData callback when provided', () => {
      const mockOnData = jest.fn();
      let onDataCallback: (data: string) => void;
      mockTerminal.onData.mockImplementation((callback) => {
        onDataCallback = callback;
      });

      renderHook(() =>
        useTerminal({ sessionId: 'test-session', onData: mockOnData })
      );

      act(() => {
        onDataCallback!('user input');
      });

      expect(mockOnData).toHaveBeenCalledWith('user input');
    });

    it('should resize terminal via WebSocket', () => {
      let onResizeCallback: (size: { cols: number; rows: number }) => void;
      mockTerminal.onResize.mockImplementation((callback) => {
        onResizeCallback = callback;
      });

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        onResizeCallback!({ cols: 80, rows: 24 });
      });

      expect(mockResizeTerminal).toHaveBeenCalledWith('test-session', 80, 24);
    });
  });

  describe('WebSocket event handling', () => {
    it('should handle terminal data events', () => {
      let terminalDataHandler: (data: any) => void;
      mockOn.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          terminalDataHandler = handler;
        }
      });

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        terminalDataHandler!({
          sessionId: 'test-session',
          data: 'incoming data',
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('incoming data');
    });

    it('should ignore data for other sessions', () => {
      let terminalDataHandler: (data: any) => void;
      mockOn.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          terminalDataHandler = handler;
        }
      });

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        terminalDataHandler!({
          sessionId: 'other-session',
          data: 'incoming data',
        });
      });

      expect(mockTerminal.write).not.toHaveBeenCalled();
    });

    it('should handle terminal error events', () => {
      let terminalErrorHandler: (data: any) => void;
      mockOn.mockImplementation((event, handler) => {
        if (event === 'terminal-error') {
          terminalErrorHandler = handler;
        }
      });

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        terminalErrorHandler!({
          sessionId: 'test-session',
          error: 'Test error',
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\x1b[31mTest error\x1b[0m\r\n');
    });

    it('should handle connection change events', () => {
      let connectionChangeHandler: (connected: boolean) => void;
      mockOn.mockImplementation((event, handler) => {
        if (event === 'connection-change') {
          connectionChangeHandler = handler;
        }
      });

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        connectionChangeHandler!(true);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('\x1b[32mConnected')
      );

      act(() => {
        connectionChangeHandler!(false);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('\x1b[31mDisconnected')
      );
    });
  });

  describe('scroll management', () => {
    it('should provide scroll functions', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      expect(typeof result.current.scrollToBottom).toBe('function');
      expect(typeof result.current.scrollToTop).toBe('function');
      expect(typeof result.current.isAtBottom).toBe('boolean');
      expect(typeof result.current.hasNewOutput).toBe('boolean');
    });

    it('should track scroll position', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Initial state should be at bottom
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
    });
  });

  describe('cleanup', () => {
    it('should cleanup terminal on unmount', () => {
      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      unmount();

      expect(mockTerminal.dispose).toHaveBeenCalled();
      expect(mockOff).toHaveBeenCalledTimes(3); // For each event type
    });

    it('should cleanup window resize listener', () => {
      const removeEventListenerSpy = jest.spyOn(window, 'removeEventListener');

      const { unmount } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      unmount();

      expect(removeEventListenerSpy).toHaveBeenCalledWith('resize', expect.any(Function));
    });
  });

  describe('error handling', () => {
    it('should handle terminal initialization errors', () => {
      MockedTerminal.mockImplementation(() => {
        throw new Error('Terminal init failed');
      });

      expect(() => {
        renderHook(() => useTerminal({ sessionId: 'test-session' }));
      }).toThrow('Terminal init failed');
    });

    it('should handle operations on disposed terminal gracefully', () => {
      const { result } = renderHook(() =>
        useTerminal({ sessionId: 'test-session' })
      );

      // Dispose the terminal
      act(() => {
        result.current.destroyTerminal();
      });

      // Operations should not throw
      expect(() => {
        result.current.writeToTerminal('test');
        result.current.clearTerminal();
        result.current.focusTerminal();
        result.current.fitTerminal();
      }).not.toThrow();
    });
  });

  describe('window resize handling', () => {
    it('should handle window resize events', () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      // Trigger window resize
      act(() => {
        window.dispatchEvent(new Event('resize'));
        jest.advanceTimersByTime(100);
      });

      expect(mockFitAddon.fit).toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('should debounce resize calls', () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      // Trigger multiple rapid resize events
      act(() => {
        window.dispatchEvent(new Event('resize'));
        window.dispatchEvent(new Event('resize'));
        window.dispatchEvent(new Event('resize'));
        jest.advanceTimersByTime(50); // Not enough to trigger
      });

      expect(mockFitAddon.fit).not.toHaveBeenCalled();

      act(() => {
        jest.advanceTimersByTime(100); // Now enough to trigger
      });

      // Should only be called once due to debouncing
      expect(mockFitAddon.fit).toHaveBeenCalledTimes(1);

      jest.useRealTimers();
    });
  });
});