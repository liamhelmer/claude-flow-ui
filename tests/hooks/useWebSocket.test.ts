import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';

// Mock the WebSocket client
jest.mock('@/lib/websocket/client', () => ({
  wsClient: {
    connected: false,
    connecting: false,
    connect: jest.fn(),
    disconnect: jest.fn(),
    sendMessage: jest.fn(),
    send: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
  },
}));

// Mock the store
jest.mock('@/lib/state/store', () => ({
  useAppStore: jest.fn(() => ({
    setError: jest.fn(),
    setLoading: jest.fn(),
  })),
}));

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useWebSocket', () => {
  let mockSetError: jest.Mock;
  let mockSetLoading: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    mockSetError = jest.fn();
    mockSetLoading = jest.fn();
    
    mockUseAppStore.mockReturnValue({
      setError: mockSetError,
      setLoading: mockSetLoading,
    });

    // Reset wsClient state
    mockWsClient.connected = false;
    mockWsClient.connecting = false;
    mockWsClient.connect.mockClear();
    mockWsClient.disconnect.mockClear();
    mockWsClient.sendMessage.mockClear();
    mockWsClient.send.mockClear();
    mockWsClient.on.mockClear();
    mockWsClient.off.mockClear();

    // Clear any existing timers
    jest.clearAllTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  describe('Hook Initialization', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    it('returns all expected methods and properties', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current).toEqual(
        expect.objectContaining({
          connected: false,
          connecting: false,
          isConnected: false,
          connect: expect.any(Function),
          disconnect: expect.any(Function),
          sendMessage: expect.any(Function),
          sendData: expect.any(Function),
          resizeTerminal: expect.any(Function),
          createSession: expect.any(Function),
          destroySession: expect.any(Function),
          listSessions: expect.any(Function),
          on: expect.any(Function),
          off: expect.any(Function),
        })
      );
    });

    it('attempts to connect automatically on mount', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);

      renderHook(() => useWebSocket());

      // Fast-forward the timeout
      act(() => {
        jest.advanceTimersByTime(150);
      });

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
      });
    });

    it('delays connection by 100ms to avoid StrictMode issues', () => {
      renderHook(() => useWebSocket());

      // Should not connect immediately
      expect(mockWsClient.connect).not.toHaveBeenCalled();

      // Should connect after timeout
      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('clears timeout on unmount', () => {
      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      // Fast-forward past the timeout
      act(() => {
        jest.advanceTimersByTime(150);
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });
  });

  describe('Connection Management', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    it('handles successful connection', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetLoading).toHaveBeenCalledWith(true);
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
      expect(mockSetError).toHaveBeenCalledWith(null);
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('handles connection errors', async () => {
      const error = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(error);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetLoading).toHaveBeenCalledWith(true);
      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('prevents multiple simultaneous connections', async () => {
      mockWsClient.connect.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)));
      
      const { result } = renderHook(() => useWebSocket());

      // Start first connection
      const promise1 = act(async () => {
        await result.current.connect();
      });

      // Try to start second connection immediately
      const promise2 = act(async () => {
        await result.current.connect();
      });

      await Promise.all([promise1, promise2]);

      // Should only call connect once
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('skips connection if already connected', async () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
      expect(mockSetLoading).not.toHaveBeenCalled();
    });

    it('disconnects properly', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockWsClient.disconnect).toHaveBeenCalledTimes(1);
    });

    it('only disconnects on unmount in production', () => {
      const originalEnv = process.env.NODE_ENV;
      
      // Test development mode
      process.env.NODE_ENV = 'development';
      const { unmount: unmountDev } = renderHook(() => useWebSocket());
      
      unmountDev();
      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      // Test production mode
      process.env.NODE_ENV = 'production';
      const { unmount: unmountProd } = renderHook(() => useWebSocket());
      
      unmountProd();
      expect(mockWsClient.disconnect).toHaveBeenCalledTimes(1);

      // Restore original environment
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('sends messages when connected', () => {
      const { result } = renderHook(() => useWebSocket());
      const message = { type: 'test', data: { test: true } };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(message);
    });

    it('logs warning when sending message while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());
      const message = { type: 'test', data: { test: true } };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, message not sent:', message);

      consoleSpy.mockRestore();
    });

    it('sends data when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'echo hello');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-123',
        data: 'echo hello',
      });
    });

    it('logs warning when sending data while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'echo hello');
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send data');

      consoleSpy.mockRestore();
    });
  });

  describe('Terminal Operations', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('resizes terminal when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-123', 80, 24);
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('resize', {
        sessionId: 'session-123',
        cols: 80,
        rows: 24,
      });
    });

    it('creates session when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
    });

    it('destroys session when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('session-123');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-123',
      });
    });

    it('lists sessions when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });

    it('logs warnings for terminal operations when disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-123', 80, 24);
        result.current.createSession();
        result.current.destroySession('session-123');
        result.current.listSessions();
      });

      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot resize terminal');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot create session');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot destroy session');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot list sessions');
      expect(mockWsClient.send).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('Event Handling', () => {
    it('provides on and off methods when wsClient has them', () => {
      const { result } = renderHook(() => useWebSocket());

      const callback = jest.fn();
      
      result.current.on('test-event', callback);
      expect(mockWsClient.on).toHaveBeenCalledWith('test-event', callback);

      result.current.off('test-event', callback);
      expect(mockWsClient.off).toHaveBeenCalledWith('test-event', callback);
    });

    it('provides no-op functions when wsClient lacks on/off methods', () => {
      // Mock wsClient without on/off methods
      const wsClientWithoutEvents = {
        ...mockWsClient,
        on: undefined,
        off: undefined,
      };
      
      jest.mocked(wsClient).on = undefined as any;
      jest.mocked(wsClient).off = undefined as any;

      const { result } = renderHook(() => useWebSocket());

      // Should not throw errors
      expect(() => {
        result.current.on('test-event', jest.fn());
        result.current.off('test-event', jest.fn());
      }).not.toThrow();
    });
  });

  describe('State Synchronization', () => {
    it('reflects wsClient connected state', () => {
      const { result, rerender } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.isConnected).toBe(false);

      // Simulate connection
      mockWsClient.connected = true;
      rerender();

      expect(result.current.connected).toBe(true);
      expect(result.current.isConnected).toBe(true);
    });

    it('reflects wsClient connecting state', () => {
      const { result, rerender } = renderHook(() => useWebSocket());

      expect(result.current.connecting).toBe(false);

      // Simulate connecting
      mockWsClient.connecting = true;
      rerender();

      expect(result.current.connecting).toBe(true);
    });
  });

  describe('Error Recovery and Resilience', () => {
    it('handles store errors gracefully', async () => {
      mockSetError.mockImplementation(() => {
        throw new Error('Store error');
      });

      const { result } = renderHook(() => useWebSocket());

      // Should not crash when store methods throw
      await expect(async () => {
        await act(async () => {
          await result.current.connect();
        });
      }).not.toThrow();
    });

    it('handles wsClient method errors gracefully', async () => {
      mockWsClient.connect.mockImplementation(() => {
        throw new Error('Client error');
      });

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
    });

    it('maintains functionality after multiple connection attempts', async () => {
      // First attempt fails
      mockWsClient.connect
        .mockRejectedValueOnce(new Error('First attempt failed'))
        .mockResolvedValueOnce(undefined);

      const { result } = renderHook(() => useWebSocket());

      // First attempt
      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');

      // Second attempt should work
      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith(null);
    });
  });

  describe('Performance and Memory', () => {
    it('does not create new function references on each render', () => {
      const { result, rerender } = renderHook(() => useWebSocket());

      const firstRender = result.current;
      rerender();
      const secondRender = result.current;

      // Functions should be stable across renders
      expect(firstRender.connect).toBe(secondRender.connect);
      expect(firstRender.disconnect).toBe(secondRender.disconnect);
      expect(firstRender.sendMessage).toBe(secondRender.sendMessage);
      expect(firstRender.sendData).toBe(secondRender.sendData);
    });

    it('properly cleans up resources on unmount', () => {
      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      // Should not leave any pending timeouts or promises
      expect(jest.getTimerCount()).toBe(0);
    });
  });
});