/**
 * Comprehensive unit tests for useWebSocket hook
 * Tests WebSocket connection management, message handling, and error recovery
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';
import { mockSocket, MockWebSocket } from '../../mocks/websocket';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockStore = {
  setError: jest.fn(),
  setLoading: jest.fn(),
};

// Mock useAppStore
(useAppStore as jest.Mock).mockReturnValue(mockStore);

describe('useWebSocket Hook', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    MockWebSocket.reset();
    mockSocket.reset();

    // Reset wsClient mock
    mockWsClient.connected = false;
    mockWsClient.connecting = false;
    mockWsClient.connect = jest.fn().mockResolvedValue(undefined);
    mockWsClient.disconnect = jest.fn();
    mockWsClient.sendMessage = jest.fn();
    mockWsClient.send = jest.fn();
    mockWsClient.on = jest.fn();
    mockWsClient.off = jest.fn();

    // Mock document.querySelector for production disconnect logic
    document.querySelector = jest.fn(() => null);
  });

  describe('Connection Management', () => {
    it('initializes with correct default values', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(false);
    });

    it('connects successfully', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).toHaveBeenCalled();
      expect(mockStore.setLoading).toHaveBeenCalledWith(true);
      expect(mockStore.setLoading).toHaveBeenCalledWith(false);
      expect(mockStore.setError).toHaveBeenCalledWith(null);
    });

    it('handles connection errors', async () => {
      const connectionError = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(connectionError);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockStore.setError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockStore.setLoading).toHaveBeenCalledWith(false);
    });

    it('prevents multiple simultaneous connections', async () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = false;

      const { result } = renderHook(() => useWebSocket());

      const connectPromise1 = act(async () => {
        await result.current.connect();
      });

      const connectPromise2 = act(async () => {
        await result.current.connect();
      });

      await Promise.all([connectPromise1, connectPromise2]);

      // Should only call connect once
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('skips connection when already connected', async () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });

    it('disconnects correctly', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('Message Handling', () => {
    it('sends messages when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      const testMessage = { type: 'test', data: 'hello' };

      act(() => {
        result.current.sendMessage(testMessage);
      });

      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(testMessage);
    });

    it('warns when sending message while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      const testMessage = { type: 'test', data: 'hello' };

      act(() => {
        result.current.sendMessage(testMessage);
      });

      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith(
        'WebSocket not connected, message not sent:',
        testMessage
      );

      consoleSpy.mockRestore();
    });

    it('sends data with proper formatting', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'ls -la\r');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-123',
        data: 'ls -la\r',
        timestamp: expect.any(Number),
      });
    });

    it('handles sendData errors gracefully', () => {
      mockWsClient.connected = true;
      mockWsClient.send.mockImplementation(() => {
        throw new Error('Send failed');
      });

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        act(() => {
          result.current.sendData('session-123', 'test');
        });
      }).not.toThrow();

      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] ❌ Failed to send data:',
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });

    it('attempts reconnection when sending data while disconnected', async () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = false;

      // Mock successful reconnection
      mockWsClient.connect.mockImplementation(async () => {
        mockWsClient.connected = true;
        return Promise.resolve();
      });

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.sendData('session-123', 'test');
      });

      expect(mockWsClient.connect).toHaveBeenCalled();
      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-123',
        data: 'test',
        timestamp: expect.any(Number),
      });
    });

    it('handles reconnection failure gracefully', async () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = false;
      mockWsClient.connect.mockRejectedValue(new Error('Reconnection failed'));

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.sendData('session-123', 'test');
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] ❌ Failed to reconnect for data send:',
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });

    it('queues data when connection is in progress', () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = true;

      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-123', 'test');
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] 🔄 Connection in progress, data send will be queued'
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Terminal Operations', () => {
    it('resizes terminal when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-123', 120, 30);
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('resize', {
        sessionId: 'session-123',
        cols: 120,
        rows: 30,
      });
    });

    it('warns when resizing while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-123', 80, 24);
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith(
        'WebSocket not connected, cannot resize terminal'
      );

      consoleSpy.mockRestore();
    });

    it('creates session when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
    });

    it('destroys session when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('session-123');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-123',
      });
    });

    it('lists sessions when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });

    it('switches session when connected', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.switchSession('new-session');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('switch-session', {
        targetSessionId: 'new-session',
      });
    });
  });

  describe('Event Handling', () => {
    it('registers event listeners with error handling', () => {
      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();

      act(() => {
        result.current.on('terminal-data', mockCallback);
      });

      expect(mockWsClient.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));

      // Test wrapped callback with error handling
      const wrappedCallback = mockWsClient.on.mock.calls[0][1];

      // Should handle callback errors gracefully
      mockCallback.mockImplementation(() => {
        throw new Error('Callback error');
      });

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      expect(() => {
        wrappedCallback('test data');
      }).not.toThrow();

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] ❌ Error in callback for terminal-data:',
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });

    it('logs listener registration for essential events', () => {
      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.on('terminal-data', jest.fn());
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 Registering listener for event: terminal-data'
      );

      consoleSpy.mockRestore();
    });

    it('warns when on method is not available', () => {
      mockWsClient.on = undefined as any;

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.on('test-event', jest.fn());
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.on is not available for event: test-event'
      );

      consoleSpy.mockRestore();
    });

    it('removes event listeners correctly', () => {
      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();

      act(() => {
        result.current.off('terminal-data', mockCallback);
      });

      expect(mockWsClient.off).toHaveBeenCalledWith('terminal-data', mockCallback);
    });

    it('warns when off method is not available', () => {
      mockWsClient.off = undefined as any;

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.off('test-event', jest.fn());
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.off is not available for event: test-event'
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Production Environment Behavior', () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = 'production';
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('delays disconnection in production', () => {
      jest.useFakeTimers();

      const { unmount } = renderHook(() => useWebSocket());

      // Mock active terminal exists
      document.querySelector = jest.fn(() => ({})) as any;

      unmount();

      // Should not disconnect immediately
      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      // Should disconnect after delay when no terminals
      document.querySelector = jest.fn(() => null);
      jest.advanceTimersByTime(100);

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('preserves connection when other terminals are active', () => {
      jest.useFakeTimers();

      const { unmount } = renderHook(() => useWebSocket());

      // Mock active terminal exists
      document.querySelector = jest.fn(() => ({})) as any;
      mockWsClient.connected = true;

      unmount();

      jest.advanceTimersByTime(100);

      // Should not disconnect when terminals are active
      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('stores pending disconnect timer for cancellation', () => {
      jest.useFakeTimers();

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      // Should store timer reference
      expect((mockWsClient as any)._pendingDisconnect).toBeDefined();

      jest.useRealTimers();
    });
  });

  describe('Development Environment Behavior', () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = 'development';
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('logs more verbose information in development', () => {
      const consoleSpy = jest.spyOn(console, 'debug').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.on('custom-event', jest.fn());
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 Registering listener for event: custom-event'
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Error Recovery', () => {
    it('handles WebSocket client initialization errors', () => {
      // Mock wsClient to be null/undefined
      const originalWsClient = mockWsClient.connect;
      mockWsClient.connect = null as any;

      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        act(() => {
          result.current.sendMessage({ type: 'test', data: 'test' });
        });
      }).not.toThrow();

      // Restore
      mockWsClient.connect = originalWsClient;
    });

    it('recovers from connection state inconsistencies', async () => {
      // Set up inconsistent state
      mockWsClient.connected = true;
      mockWsClient.connecting = true;

      const { result } = renderHook(() => useWebSocket());

      // Should handle inconsistent state gracefully
      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
    });

    it('handles simultaneous connection attempts', async () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = false;

      let resolveConnect: () => void;
      const connectPromise = new Promise<void>((resolve) => {
        resolveConnect = resolve;
      });

      mockWsClient.connect.mockImplementation(async () => {
        mockWsClient.connecting = true;
        await connectPromise;
        mockWsClient.connecting = false;
        mockWsClient.connected = true;
      });

      const { result } = renderHook(() => useWebSocket());

      // Start multiple connections
      const promise1 = act(async () => {
        await result.current.connect();
      });

      const promise2 = act(async () => {
        await result.current.connect();
      });

      const promise3 = act(async () => {
        await result.current.connect();
      });

      // Resolve all connections
      resolveConnect!();

      await Promise.all([promise1, promise2, promise3]);

      // Should only call connect once
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Memory Management', () => {
    it('cleans up references on unmount', () => {
      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      // Verify no memory leaks or hanging references
      // This is more about ensuring the unmount doesn't throw
      expect(() => unmount()).not.toThrow();
    });

    it('handles multiple unmounts gracefully', () => {
      const { unmount } = renderHook(() => useWebSocket());

      expect(() => {
        unmount();
        unmount();
        unmount();
      }).not.toThrow();
    });
  });

  describe('Edge Cases', () => {
    it('handles undefined sessionId in sendData', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        act(() => {
          result.current.sendData(undefined as any, 'test');
        });
      }).not.toThrow();
    });

    it('handles null data in sendData', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        act(() => {
          result.current.sendData('session-123', null as any);
        });
      }).not.toThrow();
    });

    it('handles very large data payloads', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      const largeData = 'a'.repeat(1024 * 1024); // 1MB string

      expect(() => {
        act(() => {
          result.current.sendData('session-123', largeData);
        });
      }).not.toThrow();
    });

    it('handles rapid successive operations', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        for (let i = 0; i < 100; i++) {
          act(() => {
            result.current.sendData(`session-${i}`, `data-${i}`);
            result.current.sendMessage({ type: 'test', data: i });
          });
        }
      }).not.toThrow();
    });

    it('handles WebSocket state changes during operations', () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        act(() => {
          result.current.sendData('session-123', 'test1');

          // Change state mid-operation
          mockWsClient.connected = false;

          result.current.sendData('session-123', 'test2');

          // Change state again
          mockWsClient.connected = true;

          result.current.sendData('session-123', 'test3');
        });
      }).not.toThrow();
    });
  });
});