import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useWebSocket - Enhanced Comprehensive Tests', () => {
  let mockSetError: jest.Mock;
  let mockSetLoading: jest.Mock;
  let mockConnect: jest.Mock;
  let mockDisconnect: jest.Mock;
  let mockSendMessage: jest.Mock;
  let mockSend: jest.Mock;
  let mockOn: jest.Mock;
  let mockOff: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    mockSetError = jest.fn();
    mockSetLoading = jest.fn();
    mockConnect = jest.fn();
    mockDisconnect = jest.fn();
    mockSendMessage = jest.fn();
    mockSend = jest.fn();
    mockOn = jest.fn();
    mockOff = jest.fn();

    mockUseAppStore.mockReturnValue({
      setError: mockSetError,
      setLoading: mockSetLoading,
    });

    Object.assign(mockWsClient, {
      connected: false,
      connecting: false,
      connect: mockConnect,
      disconnect: mockDisconnect,
      sendMessage: mockSendMessage,
      send: mockSend,
      on: mockOn,
      off: mockOff,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Connection Management', () => {
    it('should auto-connect on mount with delay', async () => {
      mockConnect.mockResolvedValue(undefined);

      renderHook(() => useWebSocket());

      expect(mockConnect).not.toHaveBeenCalled();

      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(mockConnect).toHaveBeenCalled();
        expect(mockSetLoading).toHaveBeenCalledWith(true);
      });
    });

    it('should handle successful connection', async () => {
      mockConnect.mockResolvedValue(undefined);

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(mockSetError).toHaveBeenCalledWith(null);
        expect(mockSetLoading).toHaveBeenCalledWith(false);
      });
    });

    it('should handle connection failure', async () => {
      const error = new Error('Connection failed');
      mockConnect.mockRejectedValue(error);

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
        expect(mockSetLoading).toHaveBeenCalledWith(false);
      });
    });

    it('should not connect if already connected', async () => {
      mockWsClient.connected = true;

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockConnect).not.toHaveBeenCalled();
    });

    it('should not connect if already connecting', async () => {
      mockWsClient.connecting = true;

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockConnect).not.toHaveBeenCalled();
    });

    it('should prevent duplicate connection attempts', async () => {
      mockConnect.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 1000)));

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      // Try to connect again while first connection is in progress
      act(() => {
        result.current.connect();
      });

      expect(mockConnect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('should send data when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-1', 'test data');
      });

      expect(mockSend).toHaveBeenCalledWith('data', {
        sessionId: 'session-1',
        data: 'test data',
      });
    });

    it('should not send data when disconnected', () => {
      mockWsClient.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-1', 'test data');
      });

      expect(mockSend).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send data');

      consoleSpy.mockRestore();
    });

    it('should send resize command', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-1', 80, 24);
      });

      expect(mockSend).toHaveBeenCalledWith('resize', {
        sessionId: 'session-1',
        cols: 80,
        rows: 24,
      });
    });

    it('should send message objects', () => {
      const { result } = renderHook(() => useWebSocket());

      const message = { type: 'test', data: 'test' };

      act(() => {
        result.current.sendMessage(message as any);
      });

      expect(mockSendMessage).toHaveBeenCalledWith(message);
    });

    it('should not send message when disconnected', () => {
      mockWsClient.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      const message = { type: 'test', data: 'test' };

      act(() => {
        result.current.sendMessage(message as any);
      });

      expect(mockSendMessage).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, message not sent:', message);

      consoleSpy.mockRestore();
    });
  });

  describe('Session Management', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('should create session', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockSend).toHaveBeenCalledWith('create', {});
    });

    it('should destroy session', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('session-1');
      });

      expect(mockSend).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-1',
      });
    });

    it('should list sessions', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockSend).toHaveBeenCalledWith('list', {});
    });

    it('should not perform session operations when disconnected', () => {
      mockWsClient.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
        result.current.destroySession('session-1');
        result.current.listSessions();
        result.current.resizeTerminal('session-1', 80, 24);
      });

      expect(mockSend).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot create session');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot destroy session');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot list sessions');
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot resize terminal');

      consoleSpy.mockRestore();
    });
  });

  describe('Event Handling', () => {
    it('should expose event handlers from client', () => {
      const { result } = renderHook(() => useWebSocket());

      const handler = jest.fn();

      act(() => {
        result.current.on('test-event', handler);
      });

      expect(mockOn).toHaveBeenCalledWith('test-event', handler);
    });

    it('should handle missing event handlers gracefully', () => {
      mockWsClient.on = undefined as any;
      mockWsClient.off = undefined as any;

      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        result.current.on('test-event', jest.fn());
        result.current.off('test-event', jest.fn());
      }).not.toThrow();
    });
  });

  describe('Cleanup and Unmounting', () => {
    it('should not disconnect on unmount in development', () => {
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      unmount();

      expect(mockDisconnect).not.toHaveBeenCalled();
    });

    it('should disconnect on unmount in production', () => {
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      unmount();

      expect(mockDisconnect).toHaveBeenCalled();
    });

    it('should clear timer on unmount', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
    });
  });

  describe('Connection State', () => {
    it('should return correct connection state', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(mockWsClient.connected);
      expect(result.current.connecting).toBe(mockWsClient.connecting);
      expect(result.current.isConnected).toBe(mockWsClient.connected);
    });

    it('should update when connection state changes', () => {
      const { result, rerender } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);

      mockWsClient.connected = true;
      rerender();

      expect(result.current.connected).toBe(true);
      expect(result.current.isConnected).toBe(true);
    });
  });

  describe('Error Scenarios', () => {
    it('should handle network errors during connection', async () => {
      const networkError = new Error('Network unavailable');
      mockConnect.mockRejectedValue(networkError);

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith('[useWebSocket] Failed to connect to WebSocket:', networkError);
        expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      });

      consoleSpy.mockRestore();
    });

    it('should handle timeout errors', async () => {
      const timeoutError = new Error('Connection timeout');
      mockConnect.mockRejectedValue(timeoutError);

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
        expect(mockSetLoading).toHaveBeenCalledWith(false);
      });
    });
  });

  describe('Manual Connection Control', () => {
    it('should allow manual connection', async () => {
      mockConnect.mockResolvedValue(undefined);

      const { result } = renderHook(() => useWebSocket());

      // Skip auto-connect
      act(() => {
        jest.advanceTimersByTime(100);
      });

      // Clear previous calls
      mockConnect.mockClear();
      mockSetLoading.mockClear();

      // Manual connect
      await act(async () => {
        await result.current.connect();
      });

      expect(mockConnect).toHaveBeenCalled();
      expect(mockSetLoading).toHaveBeenCalledWith(true);
    });

    it('should allow manual disconnection', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockDisconnect).toHaveBeenCalled();
    });
  });

  describe('Loading State Management', () => {
    it('should manage loading state correctly during connection', async () => {
      let resolveConnection: () => void;
      const connectionPromise = new Promise<void>(resolve => {
        resolveConnection = resolve;
      });
      mockConnect.mockReturnValue(connectionPromise);

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(mockSetLoading).toHaveBeenCalledWith(true);
      });

      act(() => {
        resolveConnection!();
      });

      await waitFor(() => {
        expect(mockSetLoading).toHaveBeenCalledWith(false);
      });
    });

    it('should reset loading state on connection error', async () => {
      const error = new Error('Connection failed');
      mockConnect.mockRejectedValue(error);

      renderHook(() => useWebSocket());

      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(mockSetLoading).toHaveBeenCalledWith(true);
      });

      await waitFor(() => {
        expect(mockSetLoading).toHaveBeenCalledWith(false);
      });
    });
  });
});