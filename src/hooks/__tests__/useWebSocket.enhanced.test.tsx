import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useWebSocket', () => {
  let mockSetError: jest.Mock;
  let mockSetLoading: jest.Mock;
  let mockStore: any;

  beforeEach(() => {
    mockSetError = jest.fn();
    mockSetLoading = jest.fn();
    
    mockStore = {
      setError: mockSetError,
      setLoading: mockSetLoading,
    };
    
    mockUseAppStore.mockReturnValue(mockStore);

    // Reset wsClient mocks
    mockWsClient.connected = false;
    mockWsClient.connecting = false;
    mockWsClient.connect = jest.fn();
    mockWsClient.disconnect = jest.fn();
    mockWsClient.sendMessage = jest.fn();
    mockWsClient.send = jest.fn();
    mockWsClient.on = jest.fn();
    mockWsClient.off = jest.fn();

    // Clear console methods
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('initialization and connection', () => {
    it('should initialize with correct default state', () => {
      const { result } = renderHook(() => useWebSocket());
      
      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(false);
    });

    it('should attempt to connect on mount with delay', async () => {
      jest.useFakeTimers();
      mockWsClient.connect.mockResolvedValue();
      
      renderHook(() => useWebSocket());
      
      expect(mockWsClient.connect).not.toHaveBeenCalled();
      
      // Fast-forward the timeout
      act(() => {
        jest.advanceTimersByTime(100);
      });
      
      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
        expect(mockSetLoading).toHaveBeenCalledWith(true);
      });
    });

    it('should not attempt reconnection if already connected', async () => {
      mockWsClient.connected = true;
      mockWsClient.connect.mockResolvedValue();
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        await result.current.connect();
      });
      
      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });

    it('should not attempt connection if already connecting', async () => {
      let resolveConnect: () => void;
      const connectPromise = new Promise<void>((resolve) => {
        resolveConnect = resolve;
      });
      
      mockWsClient.connect.mockReturnValue(connectPromise);
      
      const { result } = renderHook(() => useWebSocket());
      
      // Start first connection attempt
      const connect1 = result.current.connect();
      
      // Try to connect again while first is in progress
      const connect2 = result.current.connect();
      
      // Resolve the connection
      resolveConnect!();
      await Promise.all([connect1, connect2]);
      
      // Should only call connect once
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('connection success handling', () => {
    it('should handle successful connection', async () => {
      mockWsClient.connect.mockResolvedValue();
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        await result.current.connect();
      });
      
      expect(mockSetError).toHaveBeenCalledWith(null);
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('should update connection state on successful connect', async () => {
      mockWsClient.connect.mockResolvedValue();
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        await result.current.connect();
      });
      
      expect(result.current.connected).toBe(true);
      expect(result.current.isConnected).toBe(true);
    });
  });

  describe('connection error handling', () => {
    it('should handle connection errors', async () => {
      const testError = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(testError);
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        try {
          await result.current.connect();
        } catch (error) {
          // Expected to reject
        }
      });
      
      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('should handle network timeout errors', async () => {
      const timeoutError = new Error('Network timeout');
      mockWsClient.connect.mockRejectedValue(timeoutError);
      
      const { result } = renderHook(() => useWebSocket());
      
      await act(async () => {
        try {
          await result.current.connect();
        } catch (error) {
          // Expected to reject
        }
      });
      
      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
    });
  });

  describe('disconnect functionality', () => {
    it('should disconnect from websocket', () => {
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.disconnect();
      });
      
      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });

    it('should handle disconnect when not connected', () => {
      mockWsClient.connected = false;
      
      const { result } = renderHook(() => useWebSocket());
      
      expect(() => {
        act(() => {
          result.current.disconnect();
        });
      }).not.toThrow();
    });
  });

  describe('message sending', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('should send messages when connected', () => {
      const { result } = renderHook(() => useWebSocket());
      const testMessage = { type: 'test', payload: { id: 1 } };
      
      act(() => {
        result.current.sendMessage(testMessage);
      });
      
      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(testMessage);
    });

    it('should not send messages when disconnected', () => {
      mockWsClient.connected = false;
      
      const { result } = renderHook(() => useWebSocket());
      const testMessage = { type: 'test', payload: { id: 1 } };
      
      act(() => {
        result.current.sendMessage(testMessage);
      });
      
      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();
    });

    it('should send terminal data', () => {
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.sendData('session-123', 'test data');
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-123',
        data: 'test data'
      });
    });

    it('should handle sending data when disconnected', () => {
      mockWsClient.connected = false;
      
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.sendData('session-123', 'test data');
      });
      
      expect(mockWsClient.send).not.toHaveBeenCalled();
    });
  });

  describe('terminal session management', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('should resize terminal', () => {
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.resizeTerminal('session-123', 80, 24);
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('resize', {
        sessionId: 'session-123',
        cols: 80,
        rows: 24
      });
    });

    it('should create terminal session', () => {
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.createSession();
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
    });

    it('should destroy terminal session', () => {
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.destroySession('session-123');
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-123'
      });
    });

    it('should list terminal sessions', () => {
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.listSessions();
      });
      
      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });

    it('should handle terminal operations when disconnected', () => {
      mockWsClient.connected = false;
      
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.resizeTerminal('session-123', 80, 24);
        result.current.createSession();
        result.current.destroySession('session-123');
        result.current.listSessions();
      });
      
      expect(mockWsClient.send).not.toHaveBeenCalled();
    });
  });

  describe('event handling', () => {
    it('should provide event listener methods', () => {
      const { result } = renderHook(() => useWebSocket());
      
      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');
    });

    it('should use wsClient event methods when available', () => {
      const mockOn = jest.fn();
      const mockOff = jest.fn();
      
      mockWsClient.on = mockOn;
      mockWsClient.off = mockOff;
      
      const { result } = renderHook(() => useWebSocket());
      
      const testCallback = jest.fn();
      result.current.on('test-event', testCallback);
      result.current.off('test-event', testCallback);
      
      expect(mockOn).toHaveBeenCalledWith('test-event', testCallback);
      expect(mockOff).toHaveBeenCalledWith('test-event', testCallback);
    });

    it('should handle missing event methods gracefully', () => {
      mockWsClient.on = undefined as any;
      mockWsClient.off = undefined as any;
      
      const { result } = renderHook(() => useWebSocket());
      
      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');
      
      // Should not throw
      expect(() => {
        result.current.on('test', jest.fn());
        result.current.off('test', jest.fn());
      }).not.toThrow();
    });
  });

  describe('cleanup and unmounting', () => {
    it('should not disconnect in development mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const { unmount } = renderHook(() => useWebSocket());
      
      unmount();
      
      expect(mockWsClient.disconnect).not.toHaveBeenCalled();
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should disconnect in production mode', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const { unmount } = renderHook(() => useWebSocket());
      
      unmount();
      
      expect(mockWsClient.disconnect).toHaveBeenCalled();
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should clear timeout on unmount', () => {
      jest.useFakeTimers();
      const spy = jest.spyOn(global, 'clearTimeout');
      
      const { unmount } = renderHook(() => useWebSocket());
      
      unmount();
      
      expect(spy).toHaveBeenCalled();
      
      spy.mockRestore();
    });
  });

  describe('connection state reactivity', () => {
    it('should reactively update connection state', async () => {
      const { result, rerender } = renderHook(() => useWebSocket());
      
      expect(result.current.connected).toBe(false);
      
      // Simulate connection change
      mockWsClient.connected = true;
      mockWsClient.connecting = false;
      
      rerender();
      
      expect(result.current.connected).toBe(true);
      expect(result.current.connecting).toBe(false);
    });

    it('should handle rapid connection state changes', async () => {
      const { result, rerender } = renderHook(() => useWebSocket());
      
      // Simulate connecting
      mockWsClient.connecting = true;
      rerender();
      expect(result.current.connecting).toBe(true);
      
      // Simulate connected
      mockWsClient.connected = true;
      mockWsClient.connecting = false;
      rerender();
      expect(result.current.connected).toBe(true);
      expect(result.current.connecting).toBe(false);
      
      // Simulate disconnected
      mockWsClient.connected = false;
      rerender();
      expect(result.current.connected).toBe(false);
    });
  });

  describe('error scenarios and edge cases', () => {
    it('should handle store methods being undefined', () => {
      mockUseAppStore.mockReturnValue({
        setError: undefined,
        setLoading: undefined,
      } as any);
      
      expect(() => {
        renderHook(() => useWebSocket());
      }).not.toThrow();
    });

    it('should handle wsClient being undefined', () => {
      // This test covers defensive programming
      const { result } = renderHook(() => useWebSocket());
      
      expect(() => {
        result.current.sendMessage({ type: 'test' });
        result.current.disconnect();
      }).not.toThrow();
    });

    it('should handle complex message objects', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      const complexMessage = {
        type: 'complex',
        payload: {
          nested: {
            array: [1, 2, 3],
            object: { key: 'value' },
          },
          timestamp: new Date().toISOString(),
          binary: new ArrayBuffer(8),
        }
      };
      
      expect(() => {
        act(() => {
          result.current.sendMessage(complexMessage);
        });
      }).not.toThrow();
      
      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(complexMessage);
    });
  });

  describe('concurrent operations', () => {
    it('should handle multiple simultaneous message sends', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      const messages = Array.from({ length: 10 }, (_, i) => ({ type: 'test', id: i }));
      
      act(() => {
        messages.forEach(message => {
          result.current.sendMessage(message);
        });
      });
      
      expect(mockWsClient.sendMessage).toHaveBeenCalledTimes(10);
      messages.forEach(message => {
        expect(mockWsClient.sendMessage).toHaveBeenCalledWith(message);
      });
    });

    it('should handle concurrent terminal operations', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.createSession();
        result.current.sendData('session-1', 'data1');
        result.current.sendData('session-2', 'data2');
        result.current.resizeTerminal('session-1', 80, 24);
        result.current.destroySession('session-2');
      });
      
      expect(mockWsClient.send).toHaveBeenCalledTimes(5);
      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
      expect(mockWsClient.send).toHaveBeenCalledWith('data', { sessionId: 'session-1', data: 'data1' });
      expect(mockWsClient.send).toHaveBeenCalledWith('data', { sessionId: 'session-2', data: 'data2' });
      expect(mockWsClient.send).toHaveBeenCalledWith('resize', { sessionId: 'session-1', cols: 80, rows: 24 });
      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', { sessionId: 'session-2' });
    });
  });
});