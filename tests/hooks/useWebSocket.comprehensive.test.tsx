import { renderHook, act } from '@testing-library/react';
import { waitFor } from '@testing-library/dom';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockWsClient = {
  connected: false,
  connecting: false,
  connect: jest.fn(),
  disconnect: jest.fn(),
  sendMessage: jest.fn(),
  send: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
};

const mockSetError = jest.fn();
const mockSetLoading = jest.fn();

describe('useWebSocket - Comprehensive Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Mock the wsClient
    const { wsClient } = require('@/lib/websocket/client');
    Object.assign(wsClient, mockWsClient);

    // Mock the store
    const { useAppStore } = require('@/lib/state/store');
    useAppStore.mockReturnValue({
      setError: mockSetError,
      setLoading: mockSetLoading,
    });

    // Reset connection state
    mockWsClient.connected = false;
    mockWsClient.connecting = false;
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Connection Management', () => {
    it('attempts to connect on mount after delay', async () => {
      renderHook(() => useWebSocket());

      expect(mockWsClient.connect).not.toHaveBeenCalled();

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('does not attempt connection if already connected', async () => {
      mockWsClient.connected = true;

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });

    it('does not attempt connection if already connecting', async () => {
      mockWsClient.connecting = true;

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });

    it('sets loading state during connection', async () => {
      mockWsClient.connect.mockImplementation(() => {
        mockWsClient.connecting = true;
        return Promise.resolve();
      });

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        jest.advanceTimersByTime(100);
        await result.current.connect();
      });

      expect(mockSetLoading).toHaveBeenCalledWith(true);
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('handles connection success', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith(null);
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('handles connection failure', async () => {
      const error = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(error);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('does not disconnect on unmount in development', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('disconnects on unmount in production', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalNodeEnv;
    });
  });

  describe('Message Sending', () => {
    it('sends messages when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      const message = { type: 'test', payload: { data: 'test' } };
      result.current.sendMessage(message);

      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(message);
    });

    it('warns when sending messages while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      const message = { type: 'test', payload: { data: 'test' } };
      result.current.sendMessage(message);

      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, message not sent:', message);

      consoleSpy.mockRestore();
    });

    it('sends data when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      result.current.sendData('session-1', 'test data');

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-1',
        data: 'test data',
      });
    });

    it('warns when sending data while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      result.current.sendData('session-1', 'test data');

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send data');

      consoleSpy.mockRestore();
    });

    it('resizes terminal when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      result.current.resizeTerminal('session-1', 80, 24);

      expect(mockWsClient.send).toHaveBeenCalledWith('resize', {
        sessionId: 'session-1',
        cols: 80,
        rows: 24,
      });
    });

    it('warns when resizing terminal while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      result.current.resizeTerminal('session-1', 80, 24);

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot resize terminal');

      consoleSpy.mockRestore();
    });
  });

  describe('Session Management', () => {
    it('creates session when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      result.current.createSession();

      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
    });

    it('warns when creating session while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      result.current.createSession();

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot create session');

      consoleSpy.mockRestore();
    });

    it('destroys session when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      result.current.destroySession('session-1');

      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-1',
      });
    });

    it('warns when destroying session while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      result.current.destroySession('session-1');

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot destroy session');

      consoleSpy.mockRestore();
    });

    it('lists sessions when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      result.current.listSessions();

      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });

    it('warns when listing sessions while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      result.current.listSessions();

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot list sessions');

      consoleSpy.mockRestore();
    });
  });

  describe('Event Handling', () => {
    it('registers event listeners', () => {
      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();
      result.current.on('test-event', mockCallback);

      expect(mockWsClient.on).toHaveBeenCalledWith('test-event', mockCallback);
    });

    it('logs when registering event listeners', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();
      result.current.on('test-event', mockCallback);

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 DEBUG: Registering listener for event: test-event'
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 DEBUG: Listener registered successfully for: test-event'
      );

      consoleSpy.mockRestore();
    });

    it('warns when wsClient.on is not available', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.on = undefined;

      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();
      result.current.on('test-event', mockCallback);

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.on is not available for event: test-event'
      );

      consoleSpy.mockRestore();
    });

    it('removes event listeners', () => {
      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();
      result.current.off('test-event', mockCallback);

      expect(mockWsClient.off).toHaveBeenCalledWith('test-event', mockCallback);
    });

    it('logs when removing event listeners', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();
      result.current.off('test-event', mockCallback);

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 DEBUG: Removing listener for event: test-event'
      );

      consoleSpy.mockRestore();
    });

    it('warns when wsClient.off is not available', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockWsClient.off = undefined;

      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();
      result.current.off('test-event', mockCallback);

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.off is not available for event: test-event'
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Connection State', () => {
    it('returns correct connection state', () => {
      mockWsClient.connected = true;
      mockWsClient.connecting = false;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(true);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(true); // Alias
    });

    it('returns correct connecting state', () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = true;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(true);
      expect(result.current.isConnected).toBe(false);
    });

    it('returns correct disconnected state', () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = false;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('handles connection timeout gracefully', async () => {
      mockWsClient.connect.mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Connection timeout')), 1000);
        });
      });

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        try {
          await result.current.connect();
        } catch (error) {
          // Expected to fail
        }
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
    });

    it('handles network errors during connection', async () => {
      mockWsClient.connect.mockRejectedValue(new Error('Network error'));

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
    });

    it('prevents multiple simultaneous connection attempts', async () => {
      let resolveConnect: () => void;
      mockWsClient.connect.mockImplementation(() => {
        mockWsClient.connecting = true;
        return new Promise((resolve) => {
          resolveConnect = () => {
            mockWsClient.connecting = false;
            mockWsClient.connected = true;
            resolve(undefined);
          };
        });
      });

      const { result } = renderHook(() => useWebSocket());

      // Start first connection
      const promise1 = result.current.connect();
      
      // Try second connection while first is pending
      const promise2 = result.current.connect();

      // Both should reference the same connection attempt
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);

      // Resolve connection
      act(() => {
        resolveConnect();
      });

      await act(async () => {
        await Promise.all([promise1, promise2]);
      });

      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Manual Connection Control', () => {
    it('allows manual connection', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).toHaveBeenCalled();
    });

    it('allows manual disconnection', () => {
      const { result } = renderHook(() => useWebSocket());

      result.current.disconnect();

      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });

    it('handles disconnect when already disconnected', () => {
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      result.current.disconnect();

      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('Timer Management', () => {
    it('clears timer on unmount', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it('does not connect if unmounted before timer fires', () => {
      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });

    it('handles rapid mount/unmount cycles', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      // Mount and unmount rapidly
      for (let i = 0; i < 5; i++) {
        const { unmount } = renderHook(() => useWebSocket());
        unmount();
      }

      expect(clearTimeoutSpy).toHaveBeenCalledTimes(5);
      clearTimeoutSpy.mockRestore();
    });
  });

  describe('Development vs Production Behavior', () => {
    it('preserves connection in development on unmount', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      unmount();

      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('disconnects in production on unmount', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      unmount();

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('handles missing NODE_ENV gracefully', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      delete process.env.NODE_ENV;

      const { unmount } = renderHook(() => useWebSocket());

      expect(() => unmount()).not.toThrow();

      process.env.NODE_ENV = originalNodeEnv;
    });
  });
});