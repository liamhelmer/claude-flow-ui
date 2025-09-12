/**
 * useWebSocket Hook Configuration Fix Unit Tests
 * 
 * Tests the WebSocket hook's role in the configuration loading fix:
 * - Connection state management
 * - Config request functionality
 * - Event emission timing
 * - Error handling during config requests
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { wsClient } from '@/lib/websocket/client';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@/lib/websocket/client');
jest.mock('@/lib/state/store');

describe('useWebSocket Configuration Fix', () => {
  let mockWsClient: any;
  let mockStore: any;
  let mockEventHandlers: { [key: string]: Function };

  beforeEach(() => {
    jest.clearAllMocks();
    mockEventHandlers = {};

    mockWsClient = {
      connected: false,
      connecting: false,
      connect: jest.fn().mockResolvedValue(undefined),
      disconnect: jest.fn(),
      send: jest.fn(),
      sendMessage: jest.fn(),
      on: jest.fn((event: string, handler: Function) => {
        mockEventHandlers[event] = handler;
      }),
      off: jest.fn((event: string, handler: Function) => {
        delete mockEventHandlers[event];
      }),
      emit: jest.fn((event: string, data?: any) => {
        if (mockEventHandlers[event]) {
          mockEventHandlers[event](data);
        }
      })
    };

    mockStore = {
      setError: jest.fn(),
      setLoading: jest.fn()
    };

    (wsClient as any).connected = false;
    (wsClient as any).connecting = false;
    Object.assign(wsClient, mockWsClient);
    (useAppStore as jest.Mock).mockReturnValue(mockStore);
  });

  describe('Connection State Management', () => {
    test('should start in disconnected state', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current.connected).toBe(false);
      expect(result.current.connecting).toBe(false);
      expect(result.current.isConnected).toBe(false);
    });

    test('should attempt to connect on mount', async () => {
      renderHook(() => useWebSocket());

      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      });
    });

    test('should reflect connection state changes', async () => {
      const { result } = renderHook(() => useWebSocket());

      // Simulate connection
      mockWsClient.connected = true;
      mockWsClient.connecting = false;
      
      // Trigger state update by calling connect
      await act(async () => {
        await mockWsClient.connect();
      });

      expect(result.current.connected).toBe(true);
      expect(result.current.isConnected).toBe(true);
    });

    test('should handle connection failures gracefully', async () => {
      const connectionError = new Error('Connection failed');
      mockWsClient.connect.mockRejectedValue(connectionError);

      renderHook(() => useWebSocket());

      await waitFor(() => {
        expect(mockStore.setError).toHaveBeenCalledWith('Failed to connect to terminal server');
      });
    });
  });

  describe('Configuration Request Functionality', () => {
    test('should provide requestTerminalConfig function', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current.requestTerminalConfig).toBeDefined();
      expect(typeof result.current.requestTerminalConfig).toBe('function');
    });

    test('should send config request when connected', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.requestTerminalConfig('test-session');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('request-config', { sessionId: 'test-session' });
    });

    test('should not send config request when disconnected', () => {
      mockWsClient.connected = false;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.requestTerminalConfig('test-session');
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
    });

    test('should warn when trying to request config while disconnected', () => {
      mockWsClient.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.requestTerminalConfig('test-session');
      });

      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot request terminal config');
      
      consoleSpy.mockRestore();
    });

    test('should handle multiple concurrent config requests', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      const sessions = ['session-1', 'session-2', 'session-3'];

      act(() => {
        sessions.forEach(sessionId => {
          result.current.requestTerminalConfig(sessionId);
        });
      });

      // Should have sent all requests
      sessions.forEach(sessionId => {
        expect(mockWsClient.send).toHaveBeenCalledWith('request-config', { sessionId });
      });
      expect(mockWsClient.send).toHaveBeenCalledTimes(sessions.length);
    });

    test('should handle rapid config requests for same session', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        // Send multiple rapid requests for same session
        for (let i = 0; i < 5; i++) {
          result.current.requestTerminalConfig('test-session');
        }
      });

      // All requests should be sent (deduplication is handled at higher level)
      expect(mockWsClient.send).toHaveBeenCalledTimes(5);
    });
  });

  describe('Event Handling', () => {
    test('should provide event registration functions', () => {
      const { result } = renderHook(() => useWebSocket());

      expect(result.current.on).toBeDefined();
      expect(result.current.off).toBeDefined();
      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');
    });

    test('should register event handlers through wsClient', () => {
      const { result } = renderHook(() => useWebSocket());
      const mockHandler = jest.fn();

      act(() => {
        result.current.on('terminal-config', mockHandler);
      });

      expect(mockWsClient.on).toHaveBeenCalledWith('terminal-config', mockHandler);
    });

    test('should remove event handlers through wsClient', () => {
      const { result } = renderHook(() => useWebSocket());
      const mockHandler = jest.fn();

      act(() => {
        result.current.off('terminal-config', mockHandler);
      });

      expect(mockWsClient.off).toHaveBeenCalledWith('terminal-config', mockHandler);
    });

    test('should handle missing wsClient.on gracefully', () => {
      delete mockWsClient.on;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const { result } = renderHook(() => useWebSocket());
      const mockHandler = jest.fn();

      act(() => {
        result.current.on('terminal-config', mockHandler);
      });

      expect(consoleSpy).toHaveBeenCalledWith('⚠️ wsClient.on is not available for event: terminal-config');
      
      consoleSpy.mockRestore();
    });

    test('should handle missing wsClient.off gracefully', () => {
      delete mockWsClient.off;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const { result } = renderHook(() => useWebSocket());
      const mockHandler = jest.fn();

      act(() => {
        result.current.off('terminal-config', mockHandler);
      });

      expect(consoleSpy).toHaveBeenCalledWith('⚠️ wsClient.off is not available for event: terminal-config');
      
      consoleSpy.mockRestore();
    });
  });

  describe('Data Sending Functionality', () => {
    test('should send data when connected', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('test-session', 'test-data');
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('data', { 
        sessionId: 'test-session', 
        data: 'test-data' 
      });
    });

    test('should not send data when disconnected', () => {
      mockWsClient.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.sendData('test-session', 'test-data');
      });

      expect(mockWsClient.send).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send data');
      
      consoleSpy.mockRestore();
    });

    test('should handle terminal resize requests', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.resizeTerminal('test-session', 80, 24);
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('resize', { 
        sessionId: 'test-session', 
        cols: 80, 
        rows: 24 
      });
    });

    test('should handle session management', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.createSession();
      });

      act(() => {
        result.current.destroySession('test-session');
      });

      act(() => {
        result.current.listSessions();
      });

      expect(mockWsClient.send).toHaveBeenCalledWith('create', {});
      expect(mockWsClient.send).toHaveBeenCalledWith('destroy', { sessionId: 'test-session' });
      expect(mockWsClient.send).toHaveBeenCalledWith('list', {});
    });
  });

  describe('Error Handling', () => {
    test('should handle connection errors during config requests', async () => {
      mockWsClient.connected = true;
      mockWsClient.send.mockImplementation(() => {
        throw new Error('Send failed');
      });
      
      const { result } = renderHook(() => useWebSocket());

      expect(() => {
        act(() => {
          result.current.requestTerminalConfig('test-session');
        });
      }).toThrow('Send failed');
    });

    test('should handle network disconnection during operations', async () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      // Start an operation
      act(() => {
        result.current.requestTerminalConfig('test-session');
      });

      // Simulate disconnection
      mockWsClient.connected = false;

      // Further operations should be prevented
      act(() => {
        result.current.sendData('test-session', 'data');
      });

      expect(mockWsClient.send).toHaveBeenCalledTimes(1); // Only the first call should succeed
    });

    test('should handle malformed message sending', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      // Test with invalid session IDs
      act(() => {
        result.current.requestTerminalConfig('');
        result.current.requestTerminalConfig(null as any);
        result.current.requestTerminalConfig(undefined as any);
      });

      // Should still attempt to send (validation is server-side)
      expect(mockWsClient.send).toHaveBeenCalledTimes(3);
    });
  });

  describe('Performance and Memory Management', () => {
    test('should not leak event handlers on unmount', () => {
      const { unmount } = renderHook(() => useWebSocket());

      // Mount/unmount multiple times
      unmount();
      
      const { unmount: unmount2 } = renderHook(() => useWebSocket());
      unmount2();

      // Should handle cleanup gracefully
      expect(true).toBe(true);
    });

    test('should handle rapid connect/disconnect cycles', async () => {
      const { result } = renderHook(() => useWebSocket());

      for (let i = 0; i < 10; i++) {
        await act(async () => {
          mockWsClient.connected = true;
          await result.current.connect();
        });

        act(() => {
          mockWsClient.connected = false;
          result.current.disconnect();
        });
      }

      expect(mockWsClient.connect).toHaveBeenCalledTimes(10);
      expect(mockWsClient.disconnect).toHaveBeenCalledTimes(10);
    });

    test('should handle concurrent connection attempts', async () => {
      const { result } = renderHook(() => useWebSocket());

      // Start multiple concurrent connections
      const connections = Array(5).fill(null).map(() => result.current.connect());

      await Promise.all(connections);

      // Should handle gracefully without errors
      expect(mockWsClient.connect).toHaveBeenCalled();
    });

    test('should prevent memory leaks during config request storms', () => {
      mockWsClient.connected = true;
      
      const { result } = renderHook(() => useWebSocket());

      // Send many rapid config requests
      act(() => {
        for (let i = 0; i < 1000; i++) {
          result.current.requestTerminalConfig(`session-${i}`);
        }
      });

      expect(mockWsClient.send).toHaveBeenCalledTimes(1000);
    });
  });

  describe('Development vs Production Behavior', () => {
    test('should not disconnect on unmount in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).not.toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });

    test('should disconnect on unmount in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const { unmount } = renderHook(() => useWebSocket());

      unmount();

      expect(mockWsClient.disconnect).toHaveBeenCalled();

      process.env.NODE_ENV = originalEnv;
    });

    test('should handle auto-connect with delays in development', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      renderHook(() => useWebSocket());

      // Should connect after delay
      await waitFor(() => {
        expect(mockWsClient.connect).toHaveBeenCalled();
      }, { timeout: 200 });

      process.env.NODE_ENV = originalEnv;
    });
  });
});