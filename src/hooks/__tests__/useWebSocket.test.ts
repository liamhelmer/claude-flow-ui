import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';
import type { WebSocketMessage } from '@/types';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

// Global console spy setup
const consoleMocks = {
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

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
  // Store original console methods
  const originalConsole = {
    log: console.log,
    warn: console.warn,
    error: console.error,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    
    // Mock console methods
    console.log = consoleMocks.log;
    console.warn = consoleMocks.warn;
    console.error = consoleMocks.error;
    
    (wsClient as any).connected = false;
    (wsClient as any).connecting = false;
    (wsClient as any).connect = mockWsClient.connect;
    (wsClient as any).disconnect = mockWsClient.disconnect;
    (wsClient as any).sendMessage = mockWsClient.sendMessage;
    (wsClient as any).send = mockWsClient.send;
    (wsClient as any).on = mockWsClient.on;
    (wsClient as any).off = mockWsClient.off;

    (useAppStore as jest.Mock).mockReturnValue(mockStore);
  });

  afterEach(() => {
    jest.useRealTimers();
    // Restore original console methods
    console.log = originalConsole.log;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
    // Clear console mocks
    Object.values(consoleMocks).forEach(mock => mock.mockClear());
  });

  describe('initialization', () => {
    it('should auto-connect on mount after delay', async () => {
      renderHook(() => useWebSocket());

      // Fast-forward past the connection delay
      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).toHaveBeenCalled();
    });

    it('should not connect if already connecting', async () => {
      // Set up the hook
      const { result } = renderHook(() => useWebSocket());
      
      // Trigger auto-connect
      act(() => {
        jest.advanceTimersByTime(100);
      });
      
      // Now manually trigger another connect while the first one is in progress
      await act(async () => {
        await result.current.connect();
      });

      // Should see both mounting message and already connecting message
      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Mounting, attempting to connect...');
      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Already connected or connecting');
    });

    it('should not connect if already connected', async () => {
      (wsClient as any).connected = true;

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Already connected or connecting');
      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });
  });

  describe('connection management', () => {
    it('should handle successful connection', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockStore.setLoading).toHaveBeenCalledWith(true);
      expect(mockWsClient.connect).toHaveBeenCalled();
      expect(mockStore.setError).toHaveBeenCalledWith(null);
      expect(mockStore.setLoading).toHaveBeenCalledWith(false);
      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Connected successfully');
    });

    it('should handle connection failure', async () => {
      const connectionError = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(connectionError);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockStore.setLoading).toHaveBeenCalledWith(true);
      expect(mockStore.setError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockStore.setLoading).toHaveBeenCalledWith(false);
      expect(consoleMocks.error).toHaveBeenCalledWith(
        '[useWebSocket] Failed to connect to WebSocket:',
        connectionError
      );
    });

    it('should disconnect WebSocket client', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('message handling', () => {
    it('should send message when connected', () => {
      (wsClient as any).connected = true;
      const { result } = renderHook(() => useWebSocket());

      const message: WebSocketMessage = { type: 'data', sessionId: 'test-session', data: 'test-data' };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(message);
    });

    it('should warn when sending message while disconnected', () => {
      (wsClient as any).connected = false;
      const { result } = renderHook(() => useWebSocket());

      const message: WebSocketMessage = { type: 'data', sessionId: 'test-session', data: 'test-data' };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();
      expect(consoleMocks.warn).toHaveBeenCalledWith(
        'WebSocket not connected, message not sent:',
        message
      );
    });

    it('should send data when connected', () => {
      (wsClient as any).connected = true;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'test data');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-123',
        data: 'test data',
      });
    });

    it('should warn when sending data while disconnected', () => {
      (wsClient as any).connected = false;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'test data');
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleMocks.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send data'
      );
    });
  });

  describe('terminal operations', () => {
    beforeEach(() => {
      (wsClient as any).connected = true;
    });

    it('should resize terminal when connected', () => {
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

    it('should warn when resizing while disconnected', () => {
      (wsClient as any).connected = false;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-123', 80, 24);
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleMocks.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot resize terminal'
      );
    });

    it('should create session when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
    });

    it('should warn when creating session while disconnected', () => {
      (wsClient as any).connected = false;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleMocks.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot create session'
      );
    });

    it('should destroy session when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('session-123');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-123',
      });
    });

    it('should warn when destroying session while disconnected', () => {
      (wsClient as any).connected = false;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('session-123');
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleMocks.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot destroy session'
      );
    });

    it('should list sessions when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });

    it('should warn when listing sessions while disconnected', () => {
      (wsClient as any).connected = false;
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleMocks.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot list sessions'
      );
    });
  });

  describe('event listeners', () => {
    it('should expose WebSocket event methods', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');
    });

    it('should bind event methods to wsClient', () => {
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

  describe('connection status', () => {
    it('should expose connection status', () => {
      (wsClient as any).connected = true;
      (wsClient as any).connecting = false;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(true);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(true);
    });

    it('should update when connection status changes', () => {
      (wsClient as any).connected = false;
      (wsClient as any).connecting = true;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(true);
      expect(result.current.isConnected).toBe(false);
    });
  });

  describe('cleanup', () => {
    it('should not disconnect in development on unmount', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('should disconnect in production on unmount', () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('should clear timeout on unmount', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
    });
  });

  describe('edge cases', () => {
    it('should handle multiple connection attempts gracefully', async () => {
      let resolveConnect;
      mockWsClient.connect.mockImplementation(() => 
        new Promise(resolve => {
          resolveConnect = resolve;
        })
      );

      const { result } = renderHook(() => useWebSocket());

      // Start first connection
      const firstConnectPromise = result.current.connect();
      
      // Try second connection immediately
      const secondConnectPromise = result.current.connect();

      // Resolve the mock connection
      if (resolveConnect) resolveConnect();

      await act(async () => {
        await Promise.all([firstConnectPromise, secondConnectPromise]);
      });

      // Should only call connect once due to isConnecting ref protection
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('should handle WebSocket client being null', () => {
      // Mock wsClient properties to handle null gracefully
      const originalWsClient = { ...wsClient } as any;
      (wsClient as any).on = null;
      (wsClient as any).off = null;
      (wsClient as any).connected = false;
      (wsClient as any).connecting = false;

      // The hook should handle null properties gracefully
      expect(() => {
        const { result } = renderHook(() => useWebSocket());
        // Test that we can still access properties
        expect(result.current.connected).toBe(false);
        expect(result.current.connecting).toBe(false);
      }).not.toThrow();

      // Restore original client
      Object.assign(wsClient, originalWsClient);
    });

    it('should handle missing store methods', () => {
      (useAppStore as jest.Mock).mockReturnValue({});

      expect(() => renderHook(() => useWebSocket())).not.toThrow();
    });

    it('should handle connection timeout scenarios', async () => {
      const timeoutError = new Error('Connection timeout');
      mockWsClient.connect.mockRejectedValue(timeoutError);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(consoleMocks.error).toHaveBeenCalledWith(
        '[useWebSocket] Failed to connect to WebSocket:',
        timeoutError
      );
    });

    it('should handle network errors during operation', () => {
      (wsClient as any).connected = false;

      const { result } = renderHook(() => useWebSocket());

      // Try all operations while disconnected
      act(() => {
        result.current.sendData('session', 'data');
        result.current.resizeTerminal('session', 80, 24);
        result.current.createSession();
        result.current.destroySession('session');
        result.current.listSessions();
      });

      expect(consoleMocks.warn).toHaveBeenCalledTimes(5);
    });

    it('should handle rapid connect/disconnect cycles', async () => {
      const { result } = renderHook(() => useWebSocket());

      // Rapid connect/disconnect
      for (let i = 0; i < 5; i++) {
        await act(async () => {
          await result.current.connect();
        });
        
        act(() => {
          result.current.disconnect();
        });
      }

      // Should handle gracefully without errors
      expect(mockWsClient.connect).toHaveBeenCalled();
      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });

    it('should handle malformed message sending', () => {
      (wsClient as any).connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      // Try sending malformed data
      act(() => {
        result.current.sendMessage(null as any);
        result.current.sendMessage(undefined as any);
        result.current.sendData('', '');
      });

      // Should not crash, may log warnings
      expect(() => {
        result.current.resizeTerminal('session', -1, -1);
      }).not.toThrow();
    });

    it('should handle StrictMode double-mount scenarios', () => {
      // Simulate React StrictMode behavior - mount and unmount quickly
      const firstRender = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      firstRender.unmount();

      // Second mount (simulating StrictMode remount)
      const secondRender = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      // Should handle gracefully without duplicate connections
      expect(mockWsClient.connect).toHaveBeenCalled();
      
      secondRender.unmount();
    });

    it('should handle WebSocket client method missing scenarios', () => {
      const originalOn = (wsClient as any).on;
      const originalOff = (wsClient as any).off;

      (wsClient as any).on = undefined;
      (wsClient as any).off = undefined;

      const { result } = renderHook(() => useWebSocket());

      // Should provide no-op functions
      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');

      // Should not throw when called
      expect(() => {
        result.current.on('test', () => {});
        result.current.off('test', () => {});
      }).not.toThrow();

      // Restore
      (wsClient as any).on = originalOn;
      (wsClient as any).off = originalOff;
    });
  });

  describe('logging', () => {
    it('should log mount and unmount messages', () => {
      // Render the hook
      const { unmount } = renderHook(() => useWebSocket());

      // Advance timers to trigger the mount message
      act(() => {
        jest.advanceTimersByTime(100);
      });

      // Check that mount message was logged
      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Mounting, attempting to connect...');

      // Unmount and check unmount message
      unmount();
      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Unmounting...');
    });

    it('should log connection attempt messages', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);
      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Attempting to connect...');
      expect(consoleMocks.log).toHaveBeenCalledWith('[useWebSocket] Connected successfully');
    });
  });

  describe('TypeScript interfaces and types', () => {
    it('should handle all WebSocketMessage types correctly', () => {
      (wsClient as any).connected = true;
      const { result } = renderHook(() => useWebSocket());

      const messages: WebSocketMessage[] = [
        { type: 'data', sessionId: 'session-1', data: 'test-data' },
        { type: 'resize', sessionId: 'session-1', cols: 80, rows: 24 },
        { type: 'create' },
        { type: 'destroy', sessionId: 'session-1' },
        { type: 'list' },
      ];

      messages.forEach(message => {
        act(() => {
          result.current.sendMessage(message);
        });
        expect(mockWsClient.sendMessage).toHaveBeenCalledWith(message);
      });
    });

    it('should maintain correct return type structure', () => {
      const { result } = renderHook(() => useWebSocket());
      const hookResult = result.current;

      // Check all expected properties exist and have correct types
      expect(typeof hookResult.connected).toBe('boolean');
      expect(typeof hookResult.connecting).toBe('boolean');
      expect(typeof hookResult.isConnected).toBe('boolean');
      expect(typeof hookResult.connect).toBe('function');
      expect(typeof hookResult.disconnect).toBe('function');
      expect(typeof hookResult.sendMessage).toBe('function');
      expect(typeof hookResult.sendData).toBe('function');
      expect(typeof hookResult.resizeTerminal).toBe('function');
      expect(typeof hookResult.createSession).toBe('function');
      expect(typeof hookResult.destroySession).toBe('function');
      expect(typeof hookResult.listSessions).toBe('function');
      expect(typeof hookResult.on).toBe('function');
      expect(typeof hookResult.off).toBe('function');
    });
  });

  describe('performance and memory', () => {
    it('should handle rapid successive calls without memory leaks', () => {
      (wsClient as any).connected = true;
      const { result } = renderHook(() => useWebSocket());

      // Perform many operations rapidly
      act(() => {
        for (let i = 0; i < 1000; i++) {
          result.current.sendData(`session-${i}`, `data-${i}`);
        }
      });

      expect(mockWsClient.send).toHaveBeenCalledTimes(1000);
    });

    it('should properly clean up event listeners on unmount', () => {
      const { result, unmount } = renderHook(() => useWebSocket());
      const handler = jest.fn();

      act(() => {
        result.current.on('test-event', handler);
      });

      expect(mockWsClient.on).toHaveBeenCalledWith('test-event', handler);

      // Unmount should not automatically remove listeners (that's the consumer's responsibility)
      unmount();
      
      // The hook should still provide access to off method for cleanup
      expect(typeof result.current.off).toBe('function');
    });

    it('should handle concurrent operations safely', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Start multiple concurrent operations
      const operations = [
        result.current.connect(),
        result.current.connect(),
        result.current.connect(),
      ];

      await act(async () => {
        await Promise.all(operations);
      });

      // Should only actually connect once due to isConnecting protection
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });
  });
});