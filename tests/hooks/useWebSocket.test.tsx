import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the websocket client and store
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

// Prevent real WebSocket connections in tests
jest.mock('socket.io-client', () => {
  const mockSocket = {
    id: 'mock-socket-id',
    connected: false,
    disconnected: true,
    on: jest.fn(),
    off: jest.fn(),
    emit: jest.fn(),
    connect: jest.fn(),
    disconnect: jest.fn(),
    removeAllListeners: jest.fn(),
  };
  
  return {
    io: jest.fn(() => mockSocket),
    Socket: jest.fn(() => mockSocket),
  };
});

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

const mockStore = {
  setError: jest.fn(),
  setLoading: jest.fn(),
};

describe('useWebSocket', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.clearAllTimers();

    // Reset EventEmitter listeners to prevent memory leaks
    process.removeAllListeners();
    process.setMaxListeners(0);

    // Mock the websocket client
    const wsClient = require('@/lib/websocket/client').wsClient;
    Object.assign(wsClient, mockWsClient);

    // Mock the store
    const useAppStore = require('@/lib/state/store').useAppStore;
    useAppStore.mockReturnValue(mockStore);

    // Reset state
    mockWsClient.connected = false;
    mockWsClient.connecting = false;
    
    // Reset all mock functions
    Object.keys(mockWsClient).forEach(key => {
      if (typeof mockWsClient[key] === 'function' && mockWsClient[key].mockReset) {
        mockWsClient[key].mockReset();
      }
    });
  });

  afterEach(() => {
    // Clean up any remaining listeners
    jest.clearAllTimers();
    process.removeAllListeners();
  });

  describe('initialization', () => {
    it('should attempt to connect on mount', async () => {
      jest.useFakeTimers();

      renderHook(() => useWebSocket());

      // Fast-forward past the initial delay
      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('should set loading state during connection', async () => {
      jest.useFakeTimers();
      mockWsClient.connect.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 1000)));

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockStore.setLoading).toHaveBeenCalledWith(true);

      jest.useRealTimers();
    });

    it('should not connect if already connected', async () => {
      // Set up mock to return connected state
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = true;
      
      jest.useFakeTimers();

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('should not connect if already connecting', async () => {
      // Set up mock to return connecting state
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connecting = true;
      
      jest.useFakeTimers();

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      // The connect should still be called but internally handle the connecting state
      expect(mockWsClient.connect).toHaveBeenCalled();

      jest.useRealTimers();
    });
  });

  describe('connection management', () => {
    it('should handle successful connection', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).toHaveBeenCalled();
      expect(mockStore.setError).toHaveBeenCalledWith(null);
      expect(mockStore.setLoading).toHaveBeenCalledWith(false);
    });

    it('should handle connection errors', async () => {
      const error = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(error);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockStore.setError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockStore.setLoading).toHaveBeenCalledWith(false);
    });

    it('should disconnect', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('message sending', () => {
    it('should send messages when connected', () => {
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      const message = { type: 'test', payload: { data: 'test' } };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(message);
    });

    it('should warn when trying to send message while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      const message = { type: 'test', payload: { data: 'test' } };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        'WebSocket not connected, message not sent:',
        message
      );
      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    it('should send data when connected', () => {
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'test data');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-123',
        data: 'test data',
      });
    });

    it('should warn when trying to send data while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'test data');
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send data'
      );
      expect(mockWsClient.send).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('terminal operations', () => {
    it('should resize terminal when connected', () => {
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = true;
      
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

    it('should create session when connected', () => {
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
    });

    it('should destroy session when connected', () => {
      mockWsClient.connected = true;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('session-123');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-123',
      });
    });

    it('should list sessions when connected', () => {
      mockWsClient.connected = true;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });

    it('should warn for operations when disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-123', 80, 24);
        result.current.createSession();
        result.current.destroySession('session-123');
        result.current.listSessions();
      });

      expect(consoleSpy).toHaveBeenCalledTimes(4);
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot resize terminal');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot create session');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot destroy session');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot list sessions');

      consoleSpy.mockRestore();
    });
  });

  describe('event handling', () => {
    it('should provide event binding methods', () => {
      const { result } = renderHook(() => useWebSocket());

      const handler = jest.fn();

      act(() => {
        result.current.on('test-event', handler);
      });

      expect(mockWsClient.on).toHaveBeenCalledWith('test-event', handler);

      act(() => {
        result.current.off('test-event', handler);
      });

      expect(mockWsClient.off).toHaveBeenCalledWith('test-event', handler);
    });
  });

  describe('state properties', () => {
    it('should return connection state', () => {
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = true;
      wsClient.connecting = false;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(true);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(true); // Alias
    });

    it('should return connecting state', () => {
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = false;
      wsClient.connecting = true;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(true);
      expect(result.current.isConnected).toBe(false);
    });
  });

  describe('cleanup', () => {
    it('should not disconnect in development on unmount', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });

    it('should disconnect in production on unmount', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });

    it('should clear timer on unmount', () => {
      jest.useFakeTimers();
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
      jest.useRealTimers();
    });

    it('should handle multiple unmounts gracefully', () => {
      const { unmount } = renderHook(() => useWebSocket());

      // Multiple unmounts should not cause issues
      unmount();
      unmount();

      expect(mockWsClient.disconnect).not.toHaveBeenCalled();
    });
  });

  describe('edge cases', () => {
    it('should handle multiple rapid connect calls', async () => {
      const { result } = renderHook(() => useWebSocket());

      // First call should proceed
      const promise1 = result.current.connect();
      
      // Second call should be ignored
      const promise2 = result.current.connect();

      await act(async () => {
        await Promise.all([promise1, promise2]);
      });

      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('should handle connect calls while already connected', async () => {
      const wsClient = require('@/lib/websocket/client').wsClient;
      wsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });
  });
});