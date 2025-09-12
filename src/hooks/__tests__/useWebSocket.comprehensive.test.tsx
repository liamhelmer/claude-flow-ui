import React from 'react';
import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockedWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockedUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useWebSocket Hook - Comprehensive Tests', () => {
  const mockSetError = jest.fn();
  const mockSetLoading = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock store methods
    mockedUseAppStore.mockReturnValue({
      setError: mockSetError,
      setLoading: mockSetLoading,
      terminalSessions: [],
      activeSessionId: null,
      sidebarOpen: true,
      loading: false,
      error: null,
      setSidebarOpen: jest.fn(),
      toggleSidebar: jest.fn(),
      setActiveSession: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
      updateSession: jest.fn(),
      createNewSession: jest.fn(),
      clearSessions: jest.fn(),
    });

    // Mock wsClient properties
    Object.defineProperty(mockedWsClient, 'connected', {
      get: jest.fn(() => false),
      configurable: true,
    });
    
    Object.defineProperty(mockedWsClient, 'connecting', {
      get: jest.fn(() => false),
      configurable: true,
    });

    // Mock wsClient methods
    mockedWsClient.connect = jest.fn().mockResolvedValue(undefined);
    mockedWsClient.disconnect = jest.fn();
    mockedWsClient.sendMessage = jest.fn();
    mockedWsClient.send = jest.fn();
    mockedWsClient.on = jest.fn();
    mockedWsClient.off = jest.fn();
  });

  describe('Connection Management', () => {
    it('should connect automatically on mount', async () => {
      const { result } = renderHook(() => useWebSocket());

      await waitFor(() => {
        expect(mockedWsClient.connect).toHaveBeenCalled();
      });

      expect(mockSetLoading).toHaveBeenCalledWith(true);
    });

    it('should handle successful connection', async () => {
      mockedWsClient.connect = jest.fn().mockResolvedValue(undefined);
      
      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith(null);
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('should handle connection failure', async () => {
      const connectionError = new Error('Connection failed');
      mockedWsClient.connect = jest.fn().mockRejectedValue(connectionError);
      
      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('should not connect if already connected', async () => {
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => true),
        configurable: true,
      });

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      // Should not call connect if already connected
      expect(mockedWsClient.connect).not.toHaveBeenCalled();
    });

    it('should not connect if already connecting', async () => {
      let resolveConnect: () => void;
      const connectPromise = new Promise<void>((resolve) => {
        resolveConnect = resolve;
      });
      
      mockedWsClient.connect = jest.fn().mockReturnValue(connectPromise);

      const { result } = renderHook(() => useWebSocket());

      // Start first connection
      act(() => {
        result.current.connect();
      });

      // Try to connect again while first is pending
      await act(async () => {
        await result.current.connect();
      });

      // Should only call connect once
      expect(mockedWsClient.connect).toHaveBeenCalledTimes(1);

      // Resolve the pending connection
      act(() => {
        resolveConnect();
      });
    });

    it('should disconnect properly', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockedWsClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => true),
        configurable: true,
      });
    });

    it('should send WebSocket messages when connected', () => {
      const { result } = renderHook(() => useWebSocket());
      const testMessage = {
        type: 'test' as const,
        sessionId: 'session-1',
        data: 'test data',
        timestamp: Date.now(),
      };

      act(() => {
        result.current.sendMessage(testMessage);
      });

      expect(mockedWsClient.sendMessage).toHaveBeenCalledWith(testMessage);
    });

    it('should not send messages when disconnected', () => {
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => false),
        configurable: true,
      });

      const { result } = renderHook(() => useWebSocket());
      const testMessage = {
        type: 'test' as const,
        sessionId: 'session-1',
        data: 'test data',
        timestamp: Date.now(),
      };

      act(() => {
        result.current.sendMessage(testMessage);
      });

      expect(mockedWsClient.sendMessage).not.toHaveBeenCalled();
    });

    it('should send terminal data when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-1', 'echo hello');
      });

      expect(mockedWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-1',
        data: 'echo hello',
      });
    });

    it('should resize terminal when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-1', 80, 24);
      });

      expect(mockedWsClient.send).toHaveBeenCalledWith('resize', {
        sessionId: 'session-1',
        cols: 80,
        rows: 24,
      });
    });
  });

  describe('Session Management', () => {
    beforeEach(() => {
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => true),
        configurable: true,
      });
    });

    it('should create new session', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      expect(mockedWsClient.send).toHaveBeenCalledWith('create', {});
    });

    it('should destroy session', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.destroySession('session-1');
      });

      expect(mockedWsClient.send).toHaveBeenCalledWith('destroy', {
        sessionId: 'session-1',
      });
    });

    it('should list sessions', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.listSessions();
      });

      expect(mockedWsClient.send).toHaveBeenCalledWith('list', {});
    });

    it('should not perform session operations when disconnected', () => {
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => false),
        configurable: true,
      });

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
        result.current.destroySession('session-1');
        result.current.listSessions();
      });

      expect(mockedWsClient.send).not.toHaveBeenCalled();
    });
  });

  describe('Event Listeners', () => {
    it('should provide event listener methods', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');
    });

    it('should bind event listeners to wsClient', () => {
      const { result } = renderHook(() => useWebSocket());
      const mockCallback = jest.fn();

      act(() => {
        result.current.on('test-event', mockCallback);
      });

      expect(mockedWsClient.on).toHaveBeenCalledWith('test-event', mockCallback);
    });

    it('should handle missing event listener methods gracefully', () => {
      mockedWsClient.on = undefined as any;
      mockedWsClient.off = undefined as any;

      const { result } = renderHook(() => useWebSocket());

      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');

      // Should not throw when called
      expect(() => {
        result.current.on('test', jest.fn());
        result.current.off('test', jest.fn());
      }).not.toThrow();
    });
  });

  describe('Connection State', () => {
    it('should return correct connection state', () => {
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => true),
        configurable: true,
      });

      Object.defineProperty(mockedWsClient, 'connecting', {
        get: jest.fn(() => false),
        configurable: true,
      });

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(true);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(true); // Alias
    });

    it('should handle connecting state', () => {
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => false),
        configurable: true,
      });

      Object.defineProperty(mockedWsClient, 'connecting', {
        get: jest.fn(() => true),
        configurable: true,
      });

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(true);
    });
  });

  describe('Environment Handling', () => {
    it('should not disconnect in development mode on unmount', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockedWsClient.disconnect).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });

    it('should disconnect in production mode on unmount', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockedWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors during connection', async () => {
      const networkError = new Error('Network unreachable');
      mockedWsClient.connect = jest.fn().mockRejectedValue(networkError);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockSetLoading).toHaveBeenCalledWith(false);
    });

    it('should handle timeout errors', async () => {
      const timeoutError = new Error('Connection timeout');
      mockedWsClient.connect = jest.fn().mockRejectedValue(timeoutError);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');
    });
  });

  describe('Memory Management', () => {
    it('should clear connection timeout on unmount', () => {
      jest.useFakeTimers();
      
      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      // Advance timers to check if connection attempt would occur
      jest.advanceTimersByTime(200);
      
      expect(mockedWsClient.connect).not.toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('should prevent multiple simultaneous connection attempts', async () => {
      let connectResolvers: Array<() => void> = [];
      mockedWsClient.connect = jest.fn().mockImplementation(() => {
        return new Promise<void>((resolve) => {
          connectResolvers.push(resolve);
        });
      });

      const { result } = renderHook(() => useWebSocket());

      // Start multiple connection attempts
      act(() => {
        result.current.connect();
        result.current.connect();
        result.current.connect();
      });

      // Only one connection attempt should be made
      expect(mockedWsClient.connect).toHaveBeenCalledTimes(1);

      // Resolve the connection
      act(() => {
        connectResolvers.forEach(resolve => resolve());
      });
    });
  });

  describe('Re-connection Logic', () => {
    it('should allow reconnection after failed attempt', async () => {
      // First attempt fails
      mockedWsClient.connect = jest.fn().mockRejectedValueOnce(new Error('Failed'));
      
      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith('Failed to connect to terminal server');

      // Reset for successful attempt
      mockedWsClient.connect = jest.fn().mockResolvedValue(undefined);
      mockSetError.mockClear();

      await act(async () => {
        await result.current.connect();
      });

      expect(mockSetError).toHaveBeenCalledWith(null);
    });

    it('should handle connection state changes correctly', async () => {
      let isConnected = false;
      Object.defineProperty(mockedWsClient, 'connected', {
        get: jest.fn(() => isConnected),
        configurable: true,
      });

      const { result, rerender } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);

      // Simulate connection
      isConnected = true;
      rerender();

      expect(result.current.connected).toBe(true);

      // Simulate disconnection
      isConnected = false;
      rerender();

      expect(result.current.connected).toBe(false);
    });
  });
});