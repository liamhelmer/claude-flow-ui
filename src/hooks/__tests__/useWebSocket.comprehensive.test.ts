/**
 * Comprehensive unit tests for useWebSocket hook
 * Tests all WebSocket functionality with mocking and edge cases
 */

import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');
jest.mock('zustand/middleware', () => ({
  devtools: (fn: any) => fn,
}));

// Mock console methods to avoid noise in tests
const mockConsole = {
  log: jest.spyOn(console, 'log').mockImplementation(),
  warn: jest.spyOn(console, 'warn').mockImplementation(),
  error: jest.spyOn(console, 'error').mockImplementation(),
};

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useWebSocket Hook - Comprehensive Tests', () => {
  let mockSetError: jest.Mock;
  let mockSetLoading: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Mock store functions
    mockSetError = jest.fn();
    mockSetLoading = jest.fn();

    mockUseAppStore.mockReturnValue({
      terminalSessions: [],
      activeSessionId: null,
      sidebarOpen: true,
      loading: false,
      error: null,
      setError: mockSetError,
      setLoading: mockSetLoading,
      setSidebarOpen: jest.fn(),
      toggleSidebar: jest.fn(),
      setActiveSession: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
      updateSession: jest.fn(),
      createNewSession: jest.fn(),
      clearSessions: jest.fn(),
    });

    // Mock wsClient default state
    mockWsClient.connected = false;
    mockWsClient.connecting = false;
    mockWsClient.connect = jest.fn();
    mockWsClient.disconnect = jest.fn();
    mockWsClient.sendMessage = jest.fn();
    mockWsClient.send = jest.fn();
    mockWsClient.on = jest.fn();
    mockWsClient.off = jest.fn();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
    mockConsole.log.mockClear();
    mockConsole.warn.mockClear();
    mockConsole.error.mockClear();
  });

  afterAll(() => {
    mockConsole.log.mockRestore();
    mockConsole.warn.mockRestore();
    mockConsole.error.mockRestore();
  });

  describe('Initial State and Connection', () => {
    it('should initialize with correct default values', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(false);
      expect(typeof result.current.connect).toBe('function');
      expect(typeof result.current.disconnect).toBe('function');
    });

    it('should auto-connect on mount after timeout', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);
      mockWsClient.connected = true;

      renderHook(() => useWebSocket());

      expect(mockWsClient.connect).not.toHaveBeenCalled();

      // Advance timer to trigger auto-connect
      act(() => {
        jest.advanceTimersByTime(100);
      });

      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
      expect(mockSetLoading).toHaveBeenCalledWith(true);

      // Wait for async connect to resolve
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 0));
      });

      expect(mockSetError).toHaveBeenCalledWith(null);
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('should not connect if already connected', async () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockWsClient.connect).not.toHaveBeenCalled();
      expect(mockConsole.log).toHaveBeenCalledWith(
        '[useWebSocket] Already connected or connecting'
      );
    });

    it('should not connect if already connecting', async () => {
      mockWsClient.connecting = false;
      mockWsClient.connected = false;
      mockWsClient.connect.mockImplementation(() => {
        mockWsClient.connecting = true;
        return new Promise(resolve => setTimeout(resolve, 100));
      });

      const { result } = renderHook(() => useWebSocket());

      // Start first connection
      const firstConnect = act(async () => {
        await result.current.connect();
      });

      // Try second connection while first is pending
      await act(async () => {
        await result.current.connect();
      });

      await firstConnect;

      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Connection Success and Error Handling', () => {
    it('should handle successful connection', async () => {
      mockWsClient.connect.mockResolvedValue(undefined);
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetLoading).toHaveBeenCalledWith(true);
      expect(mockSetError).toHaveBeenCalledWith(null);
      expect(mockSetLoading).toHaveBeenLastCalledWith(false);
      expect(mockConsole.log).toHaveBeenCalledWith(
        '[useWebSocket] Connected successfully'
      );
    });

    it('should handle connection failure', async () => {
      const connectionError = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(connectionError);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetLoading).toHaveBeenCalledWith(true);
      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockSetLoading).toHaveBeenLastCalledWith(false);
      expect(mockConsole.error).toHaveBeenCalledWith(
        '[useWebSocket] Failed to connect to WebSocket:',
        connectionError
      );
    });

    it('should handle network timeout errors', async () => {
      const timeoutError = new Error('Network timeout');
      mockWsClient.connect.mockRejectedValue(timeoutError);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockConsole.error).toHaveBeenCalledWith(
        '[useWebSocket] Failed to connect to WebSocket:',
        timeoutError
      );
    });
  });

  describe('Disconnect Functionality', () => {
    it('should disconnect from WebSocket', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockWsClient.disconnect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('should send messages when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      const testMessage = {
        type: 'data' as const,
        sessionId: 'test-session',
        data: 'test data',
      };

      act(() => {
        result.current.sendMessage(testMessage);
      });

      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(testMessage);
    });

    it('should warn when sending messages while disconnected', () => {
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      const testMessage = {
        type: 'data' as const,
        sessionId: 'test-session',
        data: 'test data',
      };

      act(() => {
        result.current.sendMessage(testMessage);
      });

      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();
      expect(mockConsole.warn).toHaveBeenCalledWith(
        'WebSocket not connected, message not sent:',
        testMessage
      );
    });

    it('should send data when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('test-session', 'test data');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'test-session',
        data: 'test data',
      });
    });

    it('should warn when sending data while disconnected', () => {
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('test-session', 'test data');
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(mockConsole.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send data'
      );
    });
  });

  describe('Terminal Operations', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('should resize terminal when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('test-session', 80, 24);
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('resize', {
        sessionId: 'test-session',
        cols: 80,
        rows: 24,
      });
    });

    it('should warn when resizing terminal while disconnected', () => {
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('test-session', 80, 24);
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(mockConsole.warn).toHaveBeenCalledWith(
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
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(mockConsole.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot create session'
      );
    });

    it('should destroy session when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('test-session');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'test-session',
      });
    });

    it('should warn when destroying session while disconnected', () => {
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('test-session');
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(mockConsole.warn).toHaveBeenCalledWith(
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
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(mockConsole.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot list sessions'
      );
    });
  });

  describe('Event Handling', () => {
    it('should register event listeners', () => {
      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();

      act(() => {
        result.current.on('test-event', mockCallback);
      });

      expect(mockWsClient.on).toHaveBeenCalledWith('test-event', mockCallback);
      expect(mockConsole.log).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 DEBUG: Registering listener for event: test-event'
      );
      expect(mockConsole.log).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 DEBUG: Listener registered successfully for: test-event'
      );
    });

    it('should handle missing on method', () => {
      mockWsClient.on = undefined as any;

      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();

      act(() => {
        result.current.on('test-event', mockCallback);
      });

      expect(mockConsole.warn).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.on is not available for event: test-event'
      );
    });

    it('should remove event listeners', () => {
      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();

      act(() => {
        result.current.off('test-event', mockCallback);
      });

      expect(mockWsClient.off).toHaveBeenCalledWith('test-event', mockCallback);
      expect(mockConsole.log).toHaveBeenCalledWith(
        '[useWebSocket] 🔧 DEBUG: Removing listener for event: test-event'
      );
    });

    it('should handle missing off method', () => {
      mockWsClient.off = undefined as any;

      const { result } = renderHook(() => useWebSocket());

      const mockCallback = jest.fn();

      act(() => {
        result.current.off('test-event', mockCallback);
      });

      expect(mockConsole.warn).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.off is not available for event: test-event'
      );
    });
  });

  describe('Connection State', () => {
    it('should reflect connection state changes', () => {
      mockWsClient.connected = true;
      mockWsClient.connecting = false;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(true);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(true);
    });

    it('should reflect connecting state', () => {
      mockWsClient.connected = false;
      mockWsClient.connecting = true;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(true);
      expect(result.current.isConnected).toBe(false);
    });
  });

  describe('Cleanup and Environment Handling', () => {
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

      act(() => {
        jest.advanceTimersByTime(100);
      });

      unmount();

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });

    it('should clear timeout on unmount', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
    });
  });

  describe('Edge Cases and Error Scenarios', () => {
    it('should handle multiple rapid connect calls', async () => {
      mockWsClient.connect.mockImplementation(() => 
        new Promise(resolve => setTimeout(resolve, 50))
      );

      const { result } = renderHook(() => useWebSocket());

      // Trigger multiple connects rapidly
      const promises = [
        act(async () => await result.current.connect()),
        act(async () => await result.current.connect()),
        act(async () => await result.current.connect()),
      ];

      await Promise.all(promises);

      // Should only connect once
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('should handle connection state changes during operations', () => {
      const { result } = renderHook(() => useWebSocket());

      // Start connected
      mockWsClient.connected = true;

      act(() => {
        result.current.sendData('session-1', 'data');
      });

      expect(mockWsClient.send).toHaveBeenCalled();

      // Disconnect during operation
      mockWsClient.connected = false;

      act(() => {
        result.current.sendData('session-2', 'more data');
      });

      expect(mockConsole.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send data'
      );
    });

    it('should handle malformed event callbacks', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.on('test-event', null as any);
      });

      expect(mockWsClient.on).toHaveBeenCalledWith('test-event', null);
    });
  });
});