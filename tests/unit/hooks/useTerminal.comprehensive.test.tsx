/**
 * Comprehensive unit tests for useTerminal hook
 * Tests terminal initialization, WebSocket integration, data handling, and cleanup
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { Terminal } from '@xterm/xterm';
import { SerializeAddon } from '@xterm/addon-serialize';
import { mockSocket, MockWebSocket } from '../../mocks/websocket';
import { terminalConfigService } from '@/services/terminal-config';

// Mock dependencies
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');
jest.mock('@/hooks/useWebSocket');
jest.mock('@/lib/state/store');
jest.mock('@/services/terminal-config');

// Mock useWebSocket hook
const mockUseWebSocket = {
  sendData: jest.fn(),
  sendMessage: jest.fn(),
  resizeTerminal: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
  connect: jest.fn().mockResolvedValue(undefined),
};

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => mockUseWebSocket,
}));

// Mock store
const mockStore = {
  setError: jest.fn(),
  setLoading: jest.fn(),
};

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => mockStore,
}));

// Mock terminal config service
const mockTerminalConfigService = terminalConfigService as jest.Mocked<typeof terminalConfigService>;

describe('useTerminal Hook', () => {
  const defaultOptions = {
    sessionId: 'test-session-123',
    config: { fontSize: 14, theme: 'dark' },
    onData: jest.fn(),
  };

  const mockBackendConfig = {
    cols: 80,
    rows: 24,
  };

  const mockTerminal = {
    write: jest.fn(),
    clear: jest.fn(),
    focus: jest.fn(),
    dispose: jest.fn(),
    onData: jest.fn(() => ({ dispose: jest.fn() })),
    open: jest.fn(),
    loadAddon: jest.fn(),
    element: {
      querySelector: jest.fn(() => ({
        scrollTop: 0,
        scrollHeight: 1000,
        clientHeight: 600,
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      })),
      scrollIntoView: jest.fn(),
    },
    cols: 80,
    rows: 24,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    MockWebSocket.reset();
    mockSocket.reset();

    // Mock Terminal constructor
    (Terminal as jest.Mock).mockImplementation(() => mockTerminal);

    // Mock SerializeAddon
    (SerializeAddon as jest.Mock).mockImplementation(() => ({
      serialize: jest.fn(() => 'terminal content'),
    }));

    // Mock terminal config service
    mockTerminalConfigService.fetchConfig.mockResolvedValue(mockBackendConfig);
    mockTerminalConfigService.clearCache.mockImplementation(() => {});

    // Reset WebSocket mock
    mockUseWebSocket.sendData.mockClear();
    mockUseWebSocket.sendMessage.mockClear();
    mockUseWebSocket.on.mockClear();
    mockUseWebSocket.off.mockClear();

    // Set up DOM element for terminal container
    document.body.innerHTML = '<div class="xterm-wrapper"></div>';
  });

  afterEach(() => {
    document.body.innerHTML = '';
    jest.useRealTimers();
  });

  describe('Hook Initialization', () => {
    it('initializes with default values', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      expect(result.current.terminal).toBeNull();
      expect(result.current.backendTerminalConfig).toBeNull();
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
      expect(result.current.configError).toBeNull();
      expect(result.current.configRequestInProgress).toBe(false);
    });

    it('fetches backend configuration on mount', async () => {
      renderHook(() => useTerminal(defaultOptions));

      await waitFor(() => {
        expect(mockTerminalConfigService.fetchConfig).toHaveBeenCalledWith('test-session-123');
      });
    });

    it('handles configuration fetch errors', async () => {
      const configError = new Error('Failed to fetch config');
      mockTerminalConfigService.fetchConfig.mockRejectedValue(configError);

      const { result } = renderHook(() => useTerminal(defaultOptions));

      await waitFor(() => {
        expect(result.current.configError).toBe('Failed to fetch config');
        expect(result.current.configRequestInProgress).toBe(false);
      });
    });

    it('creates terminal when configuration is available', async () => {
      jest.useFakeTimers();

      const { result } = renderHook(() => useTerminal(defaultOptions));

      // Wait for config to load
      await act(async () => {
        await Promise.resolve(); // Let initial effects run
        jest.runAllTimers();
      });

      // Should eventually create terminal
      await waitFor(() => {
        expect(Terminal).toHaveBeenCalled();
      });

      jest.useRealTimers();
    });
  });

  describe('Terminal Creation', () => {
    it('creates terminal with correct configuration', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(expect.objectContaining({
          cols: 80,
          rows: 24,
          fontSize: 14,
          theme: expect.objectContaining({
            background: '#1e1e1e',
            foreground: '#f0f0f0',
          }),
        }));
      });

      jest.useRealTimers();
    });

    it('loads xterm addons correctly', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      await waitFor(() => {
        expect(mockTerminal.loadAddon).toHaveBeenCalled();
      });

      jest.useRealTimers();
    });

    it('sets up terminal event handlers', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      jest.useRealTimers();
    });

    it('does not create terminal without valid dimensions', () => {
      mockTerminalConfigService.fetchConfig.mockResolvedValue({ cols: 0, rows: 0 });

      renderHook(() => useTerminal(defaultOptions));

      expect(Terminal).not.toHaveBeenCalled();
    });

    it('waits for WebSocket connection before creating terminal', async () => {
      mockUseWebSocket.isConnected = false;

      const { result } = renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
      });

      expect(Terminal).not.toHaveBeenCalled();
      expect(result.current.terminal).toBeNull();
    });
  });

  describe('WebSocket Integration', () => {
    it('registers WebSocket event listeners', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      expect(mockUseWebSocket.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockUseWebSocket.on).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockUseWebSocket.on).toHaveBeenCalledWith('connection-change', expect.any(Function));
      expect(mockUseWebSocket.on).toHaveBeenCalledWith('history-refreshed', expect.any(Function));

      jest.useRealTimers();
    });

    it('cleans up WebSocket listeners on unmount', async () => {
      jest.useFakeTimers();

      const { unmount } = renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      unmount();

      expect(mockUseWebSocket.off).toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('handles terminal data from WebSocket', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      let dataHandler: Function;
      mockUseWebSocket.on.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          dataHandler = handler;
        }
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Simulate receiving data
      const testData = {
        sessionId: 'test-session-123',
        data: 'Hello terminal!',
      };

      act(() => {
        dataHandler!(testData);
      });

      await waitFor(() => {
        expect(mockTerminal.write).toHaveBeenCalledWith('Hello terminal!');
      });

      jest.useRealTimers();
    });

    it('ignores data for wrong session', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      let dataHandler: Function;
      mockUseWebSocket.on.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          dataHandler = handler;
        }
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Simulate receiving data for wrong session
      const testData = {
        sessionId: 'wrong-session',
        data: 'Should not display',
      };

      act(() => {
        dataHandler!(testData);
      });

      expect(mockTerminal.write).not.toHaveBeenCalledWith('Should not display');

      jest.useRealTimers();
    });

    it('queues data when terminal is not ready', async () => {
      jest.useFakeTimers();

      const { result } = renderHook(() => useTerminal(defaultOptions));

      let dataHandler: Function;
      mockUseWebSocket.on.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          dataHandler = handler;
        }
      });

      // Send data before terminal is created
      const testData = {
        sessionId: 'test-session-123',
        data: 'Queued data',
      };

      act(() => {
        dataHandler!(testData);
      });

      // Now create terminal
      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Queued data should be processed
      await waitFor(() => {
        expect(mockTerminal.write).toHaveBeenCalledWith('Queued data');
      });

      jest.useRealTimers();
    });
  });

  describe('Terminal Input Handling', () => {
    it('sends user input through WebSocket', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      let onDataCallback: Function;
      mockTerminal.onData.mockImplementation((callback) => {
        onDataCallback = callback;
        return { dispose: jest.fn() };
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Simulate user input
      act(() => {
        onDataCallback!('ls -la\r');
      });

      expect(mockUseWebSocket.sendData).toHaveBeenCalledWith('test-session-123', 'ls -la\r');

      jest.useRealTimers();
    });

    it('calls onData callback when provided', async () => {
      jest.useFakeTimers();

      const onDataSpy = jest.fn();
      renderHook(() => useTerminal({ ...defaultOptions, onData: onDataSpy }));

      let onDataCallback: Function;
      mockTerminal.onData.mockImplementation((callback) => {
        onDataCallback = callback;
        return { dispose: jest.fn() };
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Simulate user input
      act(() => {
        onDataCallback!('test input');
      });

      expect(onDataSpy).toHaveBeenCalledWith('test input');

      jest.useRealTimers();
    });

    it('handles input errors gracefully', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      let onDataCallback: Function;
      mockTerminal.onData.mockImplementation((callback) => {
        onDataCallback = callback;
        return { dispose: jest.fn() };
      });

      mockUseWebSocket.sendData.mockImplementation(() => {
        throw new Error('WebSocket error');
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Should not throw when input handling fails
      expect(() => {
        act(() => {
          onDataCallback!('test');
        });
      }).not.toThrow();

      jest.useRealTimers();
    });
  });

  describe('Terminal Actions', () => {
    let hookResult: any;

    beforeEach(async () => {
      jest.useFakeTimers();

      const { result } = renderHook(() => useTerminal(defaultOptions));
      hookResult = result;

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      jest.useRealTimers();
    });

    it('focuses terminal correctly', async () => {
      const success = act(() => hookResult.current.focusTerminal());

      await waitFor(() => {
        expect(mockTerminal.focus).toHaveBeenCalled();
      });

      expect(success).toBe(true);
    });

    it('returns false when focus fails', async () => {
      mockTerminal.focus.mockImplementation(() => {
        throw new Error('Focus failed');
      });

      const success = act(() => hookResult.current.focusTerminal());

      expect(success).toBe(false);
    });

    it('clears terminal correctly', () => {
      act(() => {
        hookResult.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('writes to terminal correctly', () => {
      act(() => {
        hookResult.current.writeToTerminal('Test output');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Test output');
    });

    it('handles scroll to bottom', () => {
      const mockViewport = {
        scrollTop: 0,
        scrollHeight: 1000,
      };

      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      act(() => {
        hookResult.current.scrollToBottom();
      });

      expect(mockViewport.scrollTop).toBe(1000);
    });

    it('handles scroll to top', () => {
      const mockViewport = {
        scrollTop: 500,
        scrollHeight: 1000,
      };

      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      act(() => {
        hookResult.current.scrollToTop();
      });

      expect(mockViewport.scrollTop).toBe(0);
    });

    it('refreshes terminal and sends refresh message', () => {
      act(() => {
        hookResult.current.refreshTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
      expect(mockUseWebSocket.sendMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'refresh-history',
          sessionId: 'test-session-123',
        })
      );
    });
  });

  describe('Session Management', () => {
    it('handles session changes correctly', async () => {
      jest.useFakeTimers();

      const { result, rerender } = renderHook(
        (sessionId) => useTerminal({ ...defaultOptions, sessionId }),
        { initialProps: 'session-1' }
      );

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Change session
      rerender('session-2');

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Should clear cache and fetch new config
      expect(mockTerminalConfigService.clearCache).toHaveBeenCalled();
      expect(mockTerminalConfigService.fetchConfig).toHaveBeenCalledWith('session-2');

      jest.useRealTimers();
    });

    it('destroys terminal on session change', async () => {
      jest.useFakeTimers();

      const { rerender } = renderHook(
        (sessionId) => useTerminal({ ...defaultOptions, sessionId }),
        { initialProps: 'session-1' }
      );

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Change session
      rerender('session-2');

      expect(mockTerminal.dispose).toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('cleans up on unmount', async () => {
      jest.useFakeTimers();

      const { unmount } = renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      unmount();

      expect(mockTerminal.dispose).toHaveBeenCalled();
      expect(mockUseWebSocket.off).toHaveBeenCalled();

      jest.useRealTimers();
    });
  });

  describe('Scroll Tracking', () => {
    it('tracks scroll position correctly', async () => {
      jest.useFakeTimers();

      const { result } = renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      expect(result.current.isAtBottom).toBe(true);

      jest.useRealTimers();
    });

    it('updates scroll state on new output', async () => {
      jest.useFakeTimers();

      const { result } = renderHook(() => useTerminal(defaultOptions));

      let dataHandler: Function;
      mockUseWebSocket.on.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          dataHandler = handler;
        }
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Simulate new data when not at bottom
      const mockViewport = {
        scrollTop: 100,
        scrollHeight: 1000,
        clientHeight: 600,
      };

      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      act(() => {
        dataHandler!({
          sessionId: 'test-session-123',
          data: 'New output',
        });
      });

      await waitFor(() => {
        expect(result.current.hasNewOutput).toBe(true);
      });

      jest.useRealTimers();
    });
  });

  describe('Error Handling', () => {
    it('handles WebSocket disconnection gracefully', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      let connectionHandler: Function;
      mockUseWebSocket.on.mockImplementation((event, handler) => {
        if (event === 'connection-change') {
          connectionHandler = handler;
        }
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Simulate disconnection
      act(() => {
        connectionHandler!(false);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        expect.stringContaining('Disconnected')
      );

      jest.useRealTimers();
    });

    it('handles terminal write errors', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      let dataHandler: Function;
      mockUseWebSocket.on.mockImplementation((event, handler) => {
        if (event === 'terminal-data') {
          dataHandler = handler;
        }
      });

      mockTerminal.write.mockImplementation(() => {
        throw new Error('Write failed');
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Should not throw when write fails
      expect(() => {
        act(() => {
          dataHandler!({
            sessionId: 'test-session-123',
            data: 'test',
          });
        });
      }).not.toThrow();

      jest.useRealTimers();
    });
  });

  describe('Performance Optimizations', () => {
    it('debounces scroll position checks', async () => {
      jest.useFakeTimers();

      renderHook(() => useTerminal(defaultOptions));

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Should debounce rapid scroll events
      const mockViewport = mockTerminal.element.querySelector();
      const scrollHandler = mockViewport.addEventListener.mock.calls.find(
        call => call[0] === 'scroll'
      )?.[1];

      if (scrollHandler) {
        // Trigger multiple scroll events rapidly
        scrollHandler();
        scrollHandler();
        scrollHandler();

        // Should only process after debounce delay
        jest.advanceTimersByTime(16);
      }

      jest.useRealTimers();
    });

    it('uses refs to prevent stale closures', async () => {
      jest.useFakeTimers();

      const { result, rerender } = renderHook(
        (props) => useTerminal(props),
        { initialProps: { ...defaultOptions, onData: jest.fn() } }
      );

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Change onData callback
      const newOnData = jest.fn();
      rerender({ ...defaultOptions, onData: newOnData });

      // Terminal input should use new callback
      let onDataCallback: Function;
      mockTerminal.onData.mockImplementation((callback) => {
        onDataCallback = callback;
        return { dispose: jest.fn() };
      });

      act(() => {
        onDataCallback!('test');
      });

      expect(newOnData).toHaveBeenCalledWith('test');

      jest.useRealTimers();
    });
  });

  describe('Edge Cases', () => {
    it('handles missing sessionId', () => {
      expect(() => {
        renderHook(() => useTerminal({ ...defaultOptions, sessionId: '' }));
      }).not.toThrow();
    });

    it('handles invalid configuration', async () => {
      mockTerminalConfigService.fetchConfig.mockResolvedValue({
        cols: -1,
        rows: -1,
      });

      const { result } = renderHook(() => useTerminal(defaultOptions));

      await waitFor(() => {
        expect(result.current.terminal).toBeNull();
      });
    });

    it('handles WebSocket reconnection during input', async () => {
      jest.useFakeTimers();

      mockUseWebSocket.isConnected = false;

      renderHook(() => useTerminal(defaultOptions));

      let onDataCallback: Function;
      mockTerminal.onData.mockImplementation((callback) => {
        onDataCallback = callback;
        return { dispose: jest.fn() };
      });

      await act(async () => {
        await Promise.resolve();
        jest.runAllTimers();
      });

      // Try to send input when disconnected
      act(() => {
        onDataCallback!('test input');
      });

      // Should not throw
      expect(mockUseWebSocket.sendData).not.toHaveBeenCalled();

      jest.useRealTimers();
    });
  });
});