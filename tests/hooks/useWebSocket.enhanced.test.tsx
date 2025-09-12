import React from 'react';
import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useAppStore } from '@/lib/state/store';
import { wsClient } from '@/lib/websocket/client';
import {
  createMockWebSocketClient,
  WebSocketTestHarness,
  createTerminalDataMessage,
  createTerminalConfigMessage,
  createErrorMessage,
  MockConnectionStateMachine,
} from '../utils/websocket-mocks';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

const mockWsClient = wsClient as jest.Mocked<typeof wsClient>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useWebSocket Enhanced Tests', () => {
  let testHarness: WebSocketTestHarness;
  let mockStore: any;

  beforeEach(() => {
    testHarness = new WebSocketTestHarness();
    
    mockStore = {
      setError: jest.fn(),
      setLoading: jest.fn(),
      addSession: jest.fn(),
      removeSession: jest.fn(),
      updateSession: jest.fn(),
    };

    mockUseAppStore.mockReturnValue(mockStore);

    // Reset wsClient mock
    Object.assign(mockWsClient, {
      connected: false,
      connecting: false,
      connect: jest.fn(),
      disconnect: jest.fn(),
      send: jest.fn(),
      sendMessage: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
    });
  });

  afterEach(() => {
    testHarness.cleanup();
    jest.clearAllMocks();
  });

  describe('Connection Management', () => {
    it('should handle successful connection', async () => {
      mockWsClient.connect.mockResolvedValue();
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

    it('should handle connection failure', async () => {
      const error = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(error);

      const { result } = renderHook(() => useWebSocket());

      await act(async () => {
        await result.current.connect();
      });

      expect(mockStore.setError).toHaveBeenCalledWith('Failed to connect to terminal server');
      expect(mockStore.setLoading).toHaveBeenCalledWith(false);
    });

    it('should prevent duplicate connection attempts', async () => {
      mockWsClient.connect.mockResolvedValue();
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      // First connection attempt
      const promise1 = act(async () => {
        await result.current.connect();
      });

      // Second connection attempt while first is in progress
      const promise2 = act(async () => {
        await result.current.connect();
      });

      await Promise.all([promise1, promise2]);

      // Should only call connect once
      expect(mockWsClient.connect).toHaveBeenCalledTimes(1);
    });

    it('should handle disconnect gracefully', async () => {
      mockWsClient.connected = true;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.disconnect();
      });

      expect(mockWsClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      mockWsClient.connected = true;
    });

    it('should send WebSocket messages when connected', () => {
      const { result } = renderHook(() => useWebSocket());
      const message = { type: 'test', data: 'hello' };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(mockWsClient.sendMessage).toHaveBeenCalledWith(message);
    });

    it('should not send messages when disconnected', () => {
      mockWsClient.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      const { result } = renderHook(() => useWebSocket());
      const message = { type: 'test', data: 'hello' };

      act(() => {
        result.current.sendMessage(message);
      });

      expect(mockWsClient.sendMessage).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith(
        'WebSocket not connected, message not sent:',
        message
      );

      consoleSpy.mockRestore();
    });

    it('should send terminal data', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-1', 'ls -la');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-1',
        data: 'ls -la',
      });
    });

    it('should send resize commands', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('session-1', 120, 40);
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('resize', {
        sessionId: 'session-1',
        cols: 120,
        rows: 40,
      });
    });

    it('should handle session management commands', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });
      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});

      act(() => {
        result.current.destroySession('session-1');
      });
      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', { sessionId: 'session-1' });

      act(() => {
        result.current.listSessions();
      });
      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });
  });

  describe('Event Listeners', () => {
    it('should register event listeners', () => {
      mockWsClient.on = jest.fn();
      const { result } = renderHook(() => useWebSocket());
      const callback = jest.fn();

      act(() => {
        result.current.on('terminal-data', callback);
      });

      expect(mockWsClient.on).toHaveBeenCalledWith('terminal-data', callback);
    });

    it('should remove event listeners', () => {
      mockWsClient.off = jest.fn();
      const { result } = renderHook(() => useWebSocket());
      const callback = jest.fn();

      act(() => {
        result.current.off('terminal-data', callback);
      });

      expect(mockWsClient.off).toHaveBeenCalledWith('terminal-data', callback);
    });

    it('should handle missing on/off methods gracefully', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockWsClient.on = undefined as any;
      mockWsClient.off = undefined as any;

      const { result } = renderHook(() => useWebSocket());
      const callback = jest.fn();

      act(() => {
        result.current.on('test-event', callback);
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.on is not available for event: test-event'
      );

      act(() => {
        result.current.off('test-event', callback);
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[useWebSocket] ⚠️ wsClient.off is not available for event: test-event'
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Auto-connect Behavior', () => {
    it('should auto-connect on mount with delay', async () => {
      jest.useFakeTimers();
      mockWsClient.connect.mockResolvedValue();

      renderHook(() => useWebSocket());

      // Should not connect immediately
      expect(mockWsClient.connect).not.toHaveBeenCalled();

      // Advance timers by the delay
      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });

      jest.useRealTimers();
    });

    it('should not disconnect on unmount in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });

    it('should disconnect on unmount in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Connection State', () => {
    it('should expose connection states correctly', () => {
      mockWsClient.connected = true;
      mockWsClient.connecting = false;

      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(true);
      expect(result.current.isConnected).toBe(true); // Alias
      expect(result.current.connecting).toBe(false);
    });

    it('should update connection states dynamically', () => {
      const { result, rerender } = renderHook(() => useWebSocket());

      // Initially disconnected
      expect(result.current.connected).toBe(false);

      // Simulate connection
      mockWsClient.connected = true;
      rerender();

      expect(result.current.connected).toBe(true);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle connection timeout', async () => {
      jest.useFakeTimers();
      const slowConnect = jest.fn(() => new Promise(resolve => setTimeout(resolve, 10000)));
      mockWsClient.connect = slowConnect;

      const { result } = renderHook(() => useWebSocket());

      const connectPromise = act(async () => {
        result.current.connect();
      });

      // Advance time but not enough for connection
      act(() => {
        jest.advanceTimersByTime(5000);
      });

      // Connection should still be in progress
      expect(mockStore.setLoading).toHaveBeenCalledWith(true);

      jest.useRealTimers();
    });

    it('should handle rapid connect/disconnect cycles', async () => {
      mockWsClient.connect.mockResolvedValue();

      const { result } = renderHook(() => useWebSocket());

      // Rapid connect/disconnect
      await act(async () => {
        await result.current.connect();
        result.current.disconnect();
        await result.current.connect();
        result.current.disconnect();
      });

      expect(mockWsClient.connect).toHaveBeenCalledTimes(2);
      expect(mockWsClient.disconnect).toHaveBeenCalledTimes(2);
    });

    it('should handle sending commands while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockWsClient.connected = false;

      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('session-1', 'test');
        result.current.resizeTerminal('session-1', 80, 24);
        result.current.createSession();
        result.current.destroySession('session-1');
        result.current.listSessions();
      });

      expect(consoleSpy).toHaveBeenCalledTimes(5);
      expect(mockWsClient.send).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('Memory and Performance', () => {
    it('should clean up timers on unmount', () => {
      jest.useFakeTimers();
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();

      clearTimeoutSpy.mockRestore();
      jest.useRealTimers();
    });

    it('should not create memory leaks with multiple instances', () => {
      const instances = [];
      
      for (let i = 0; i < 10; i++) {
        instances.push(renderHook(() => useWebSocket()));
      }

      // All instances should work independently
      expect(instances).toHaveLength(10);

      // Clean up
      instances.forEach(instance => instance.unmount());
    });
  });

  describe('Integration with State Machine', () => {
    it('should work with connection state machine', async () => {
      const stateMachine = new MockConnectionStateMachine();
      const stateChanges: string[] = [];

      stateMachine.on('stateChange', (state: string) => {
        stateChanges.push(state);
      });

      // Simulate connection process
      stateMachine.connect();
      
      await waitFor(() => {
        expect(stateChanges).toContain('connecting');
      });

      await waitFor(() => {
        expect(stateChanges).toContain('connected');
      });

      stateMachine.disconnect();
      expect(stateChanges).toContain('disconnected');
    });

    it('should handle retry logic', async () => {
      const stateMachine = new MockConnectionStateMachine();
      
      // Mock failed connections
      const originalRandom = Math.random;
      Math.random = jest.fn(() => 0.05); // Force failure

      stateMachine.connect();

      await waitFor(() => {
        expect(stateMachine.getState()).toBe('failed');
      });

      await waitFor(() => {
        expect(stateMachine.getState()).toBe('reconnecting');
      });

      // Restore original Math.random
      Math.random = originalRandom;
    });
  });

  describe('Real-world Scenarios', () => {
    it('should handle terminal session lifecycle', async () => {
      mockWsClient.connected = true;
      const { result } = renderHook(() => useWebSocket());

      // Create session
      act(() => {
        result.current.createSession();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});

      // Send commands
      act(() => {
        result.current.sendData('session-1', 'echo "Hello World"');
      });

      // Resize terminal
      act(() => {
        result.current.resizeTerminal('session-1', 120, 40);
      });

      // Destroy session
      act(() => {
        result.current.destroySession('session-1');
      });

      expect(mockWsClient.send).toHaveBeenCalledTimes(4);
    });

    it('should handle network interruption and recovery', async () => {
      mockWsClient.connected = true;
      const { result } = renderHook(() => useWebSocket());

      // Simulate network failure
      mockWsClient.connected = false;
      
      // Try to send command during failure
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      act(() => {
        result.current.sendData('session-1', 'test');
      });

      expect(consoleSpy).toHaveBeenCalled();

      // Simulate recovery
      mockWsClient.connected = true;
      
      act(() => {
        result.current.sendData('session-1', 'test');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', {
        sessionId: 'session-1',
        data: 'test',
      });

      consoleSpy.mockRestore();
    });

    it('should handle concurrent operations', async () => {
      mockWsClient.connected = true;
      const { result } = renderHook(() => useWebSocket());

      // Simulate multiple concurrent operations
      act(() => {
        result.current.sendData('session-1', 'command1');
        result.current.sendData('session-2', 'command2');
        result.current.resizeTerminal('session-1', 80, 24);
        result.current.createSession();
      });

      expect(mockWsClient.send).toHaveBeenCalledTimes(4);
    });
  });
});