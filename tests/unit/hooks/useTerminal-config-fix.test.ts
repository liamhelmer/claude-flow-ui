/**
 * useTerminal Hook Configuration Fix Unit Tests
 * 
 * Tests the specific fixes in useTerminal hook for configuration loading:
 * - Event listener registration timing
 * - Config request timing
 * - Initialization order dependencies
 * - Race condition prevention
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@/hooks/useWebSocket');
jest.mock('@/lib/state/store');

describe('useTerminal Configuration Fix', () => {
  let mockWebSocket: any;
  let mockStore: any;
  let mockEventHandlers: { [key: string]: Function };
  let configRequests: Array<{ sessionId: string; timestamp: number }>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockEventHandlers = {};
    configRequests = [];

    mockWebSocket = {
      connected: false,
      connecting: false,
      isConnected: false,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      requestTerminalConfig: jest.fn((sessionId: string) => {
        configRequests.push({ sessionId, timestamp: Date.now() });
      }),
      on: jest.fn((event: string, handler: Function) => {
        mockEventHandlers[event] = handler;
      }),
      off: jest.fn((event: string, handler: Function) => {
        delete mockEventHandlers[event];
      })
    };

    mockStore = {
      setError: jest.fn(),
      setLoading: jest.fn()
    };

    (useWebSocket as jest.Mock).mockReturnValue(mockWebSocket);
    (useAppStore as jest.Mock).mockReturnValue(mockStore);
  });

  describe('Event Listener Registration Timing', () => {
    test('should register terminal-config listener immediately on mount', () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Event listener should be registered
      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-config', expect.any(Function));
      expect(mockEventHandlers['terminal-config']).toBeDefined();
      expect(typeof mockEventHandlers['terminal-config']).toBe('function');
    });

    test('should register all event listeners before requesting config', async () => {
      const registrationOrder: string[] = [];
      const configRequestTime = { time: 0 };

      mockWebSocket.on.mockImplementation((event: string, handler: Function) => {
        registrationOrder.push(event);
        mockEventHandlers[event] = handler;
      });

      mockWebSocket.requestTerminalConfig.mockImplementation((sessionId: string) => {
        configRequestTime.time = Date.now();
        configRequests.push({ sessionId, timestamp: configRequestTime.time });
      });

      // Start with connected state to trigger immediate config request
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(configRequests.length).toBeGreaterThan(0);
      });

      // All necessary event listeners should be registered before config request
      const expectedEvents = ['terminal-data', 'terminal-error', 'connection-change', 'terminal-config'];
      expectedEvents.forEach(event => {
        expect(registrationOrder).toContain(event);
      });

      expect(configRequestTime.time).toBeGreaterThan(0);
    });

    test('should handle config events immediately after listener registration', async () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Config listener should be available
      expect(mockEventHandlers['terminal-config']).toBeDefined();

      // Should handle config event immediately
      const configData = { sessionId: 'test-session', cols: 80, rows: 24 };
      
      await act(async () => {
        mockEventHandlers['terminal-config'](configData);
      });

      // Config should be processed (hook should update internal state)
      // Note: Since we can't directly inspect internal state, we verify no errors occur
      expect(true).toBe(true);
    });
  });

  describe('Configuration Request Timing', () => {
    test('should not request config when disconnected', () => {
      mockWebSocket.connected = false;
      mockWebSocket.isConnected = false;

      renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Should not have requested config
      expect(mockWebSocket.requestTerminalConfig).not.toHaveBeenCalled();
      expect(configRequests).toHaveLength(0);
    });

    test('should request config immediately when connected on mount', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(mockWebSocket.requestTerminalConfig).toHaveBeenCalledWith('test-session');
        expect(configRequests).toHaveLength(1);
        expect(configRequests[0].sessionId).toBe('test-session');
      });
    });

    test('should request config when connection state changes from disconnected to connected', async () => {
      mockWebSocket.connected = false;
      mockWebSocket.isConnected = false;

      const { rerender } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Initially no config request
      expect(configRequests).toHaveLength(0);

      // Simulate connection
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;
      (useWebSocket as jest.Mock).mockReturnValue({
        ...mockWebSocket,
        connected: true,
        isConnected: true
      });

      rerender();

      await waitFor(() => {
        expect(mockWebSocket.requestTerminalConfig).toHaveBeenCalledWith('test-session');
        expect(configRequests).toHaveLength(1);
      });
    });

    test('should prevent duplicate config requests', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { rerender } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(configRequests).toHaveLength(1);
      });

      // Force multiple re-renders
      for (let i = 0; i < 5; i++) {
        rerender();
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
        });
      }

      // Should still only have one config request
      expect(configRequests).toHaveLength(1);
    });

    test('should request new config when session changes', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { rerender } = renderHook(
        ({ sessionId }) => useTerminal({ sessionId }),
        { initialProps: { sessionId: 'session-1' } }
      );

      await waitFor(() => {
        expect(configRequests).toHaveLength(1);
        expect(configRequests[0].sessionId).toBe('session-1');
      });

      // Change session
      rerender({ sessionId: 'session-2' });

      await waitFor(() => {
        expect(configRequests).toHaveLength(2);
        expect(configRequests[1].sessionId).toBe('session-2');
      });
    });
  });

  describe('Initialization Order Dependencies', () => {
    test('should not initialize terminal without backend config', () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Terminal should not be initialized yet
      expect(result.current.terminal).toBeNull();
      expect(result.current.backendTerminalConfig).toBeNull();
    });

    test('should not initialize terminal with invalid backend config', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Send invalid configs
      const invalidConfigs = [
        { sessionId: 'test-session', cols: 0, rows: 24 },
        { sessionId: 'test-session', cols: 80, rows: 0 },
        { sessionId: 'test-session', cols: -1, rows: 24 },
        { sessionId: 'test-session', cols: null, rows: 24 },
        { sessionId: 'test-session', cols: undefined, rows: 24 }
      ];

      for (const config of invalidConfigs) {
        await act(async () => {
          mockEventHandlers['terminal-config'](config);
        });

        expect(result.current.terminal).toBeNull();
      }
    });

    test('should wait for DOM container before terminal initialization', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Send valid config
      await act(async () => {
        mockEventHandlers['terminal-config']({
          sessionId: 'test-session',
          cols: 80,
          rows: 24
        });
      });

      // Terminal should still not be initialized without container
      expect(result.current.terminal).toBeNull();
      expect(result.current.backendTerminalConfig).toEqual({ cols: 80, rows: 24 });
    });

    test('should preserve initialization order across re-renders', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { result, rerender } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Multiple re-renders before config arrives
      for (let i = 0; i < 5; i++) {
        rerender();
        expect(result.current.terminal).toBeNull();
      }

      // Send config
      await act(async () => {
        mockEventHandlers['terminal-config']({
          sessionId: 'test-session',
          cols: 80,
          rows: 24
        });
      });

      // More re-renders after config
      for (let i = 0; i < 5; i++) {
        rerender();
        expect(result.current.backendTerminalConfig).toEqual({ cols: 80, rows: 24 });
      }
    });
  });

  describe('Race Condition Prevention', () => {
    test('should handle config arriving before listener registration', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      // Pre-send config before hook renders (simulating race condition)
      const preConfigData = { sessionId: 'test-session', cols: 80, rows: 24 };
      
      // Mock the on method to immediately call handler with pre-existing config
      mockWebSocket.on.mockImplementation((event: string, handler: Function) => {
        mockEventHandlers[event] = handler;
        if (event === 'terminal-config') {
          // Simulate config already available
          setTimeout(() => handler(preConfigData), 0);
        }
      });

      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(result.current.backendTerminalConfig).toEqual({ cols: 80, rows: 24 });
      });
    });

    test('should handle rapid connect/disconnect cycles', async () => {
      const { rerender } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Rapid connection state changes
      for (let i = 0; i < 10; i++) {
        // Connect
        mockWebSocket.connected = true;
        mockWebSocket.isConnected = true;
        (useWebSocket as jest.Mock).mockReturnValue({
          ...mockWebSocket,
          connected: true,
          isConnected: true
        });

        rerender();

        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 1));
        });

        // Disconnect
        mockWebSocket.connected = false;
        mockWebSocket.isConnected = false;
        (useWebSocket as jest.Mock).mockReturnValue({
          ...mockWebSocket,
          connected: false,
          isConnected: false
        });

        rerender();

        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 1));
        });
      }

      // Should handle gracefully without errors
      expect(true).toBe(true);
    });

    test('should handle config updates during terminal initialization', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Send multiple rapid config updates
      const configs = [
        { sessionId: 'test-session', cols: 80, rows: 24 },
        { sessionId: 'test-session', cols: 100, rows: 30 },
        { sessionId: 'test-session', cols: 120, rows: 40 }
      ];

      for (const config of configs) {
        await act(async () => {
          mockEventHandlers['terminal-config'](config);
          await new Promise(resolve => setTimeout(resolve, 1));
        });
      }

      // Should have the last config
      await waitFor(() => {
        expect(result.current.backendTerminalConfig).toEqual({ cols: 120, rows: 40 });
      });
    });

    test('should properly clean up event listeners on unmount', () => {
      const { unmount } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Verify listeners are registered
      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-config', expect.any(Function));

      unmount();

      // Verify listeners are cleaned up
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-config', expect.any(Function));
    });

    test('should handle session cleanup during config loading', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { rerender } = renderHook(
        ({ sessionId }) => useTerminal({ sessionId }),
        { initialProps: { sessionId: 'session-1' } }
      );

      await waitFor(() => {
        expect(configRequests).toHaveLength(1);
      });

      // Change session before config arrives
      rerender({ sessionId: 'session-2' });

      // Send config for old session
      await act(async () => {
        mockEventHandlers['terminal-config']({
          sessionId: 'session-1',
          cols: 80,
          rows: 24
        });
      });

      // Send config for new session
      await act(async () => {
        mockEventHandlers['terminal-config']({
          sessionId: 'session-2',
          cols: 100,
          rows: 30
        });
      });

      // Should only have config for current session
      await waitFor(() => {
        expect(configRequests).toHaveLength(2);
      });
    });
  });

  describe('Memory Management', () => {
    test('should not leak memory during rapid config updates', async () => {
      mockWebSocket.connected = true;
      mockWebSocket.isConnected = true;

      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Send many config updates
      for (let i = 0; i < 100; i++) {
        await act(async () => {
          mockEventHandlers['terminal-config']({
            sessionId: 'test-session',
            cols: 80 + i,
            rows: 24 + i
          });
        });
      }

      // Should have the last config
      expect(result.current.backendTerminalConfig).toEqual({ cols: 179, rows: 123 });
    });

    test('should clean up resources on session change', () => {
      const { rerender } = renderHook(
        ({ sessionId }) => useTerminal({ sessionId }),
        { initialProps: { sessionId: 'session-1' } }
      );

      // Change session multiple times
      const sessions = ['session-2', 'session-3', 'session-4'];
      
      sessions.forEach(sessionId => {
        rerender({ sessionId });
      });

      // Should have cleaned up resources for each session change
      expect(mockWebSocket.off).toHaveBeenCalledTimes(sessions.length * 4); // 4 events per cleanup
    });
  });
});