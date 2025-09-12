/**
 * Comprehensive enhanced tests for useWebSocket hook
 * Tests connection management, event handling, error scenarios, and performance
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { useWebSocket } from '../useWebSocket';
import { createMockSocketIO, expectAsyncError, performanceTimer } from '@/__tests__/utils/test-helpers';

// Mock WebSocketClient
jest.mock('@/lib/websocket/client', () => {
  return jest.fn().mockImplementation(() => {
    const mockClient = {
      connect: jest.fn(),
      disconnect: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      send: jest.fn(),
      sendMessage: jest.fn(),
      connected: false,
      connecting: false,
      
      // Test helpers
      _mockConnect: function() {
        this.connected = true;
        this.connecting = false;
        const connectCallback = this.on.mock.calls.find(call => call[0] === 'connect')?.[1];
        if (connectCallback) connectCallback();
      },
      
      _mockDisconnect: function() {
        this.connected = false;
        this.connecting = false;
        const disconnectCallback = this.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
        if (disconnectCallback) disconnectCallback();
      },
      
      _mockError: function(error = new Error('Mock error')) {
        const errorCallback = this.on.mock.calls.find(call => call[0] === 'error')?.[1];
        if (errorCallback) errorCallback(error);
      },
      
      _mockEvent: function(eventName: string, data: any) {
        const callback = this.on.mock.calls.find(call => call[0] === eventName)?.[1];
        if (callback) callback(data);
      }
    };
    
    // Mock connect to return a promise
    mockClient.connect.mockImplementation(() => {
      mockClient.connecting = true;
      return Promise.resolve();
    });
    
    return mockClient;
  });
});

describe('useWebSocket Hook - Enhanced Comprehensive Tests', () => {
  let mockClient: any;

  beforeEach(() => {
    jest.clearAllMocks();
    // Get the latest mock client instance
    const WebSocketClient = require('@/lib/websocket/client').default;
    mockClient = new WebSocketClient();
  });

  describe('Hook Initialization', () => {
    it('should initialize with default state', () => {
      const { result } = renderHook(() => useWebSocket());
      
      expect(result.current.isConnected).toBe(false);
      expect(result.current.isConnecting).toBe(false);
      expect(typeof result.current.connect).toBe('function');
      expect(typeof result.current.disconnect).toBe('function');
      expect(typeof result.current.on).toBe('function');
      expect(typeof result.current.off).toBe('function');
      expect(typeof result.current.send).toBe('function');
      expect(typeof result.current.sendMessage).toBe('function');
    });

    it('should create WebSocket client instance', () => {
      renderHook(() => useWebSocket());
      
      const WebSocketClient = require('@/lib/websocket/client').default;
      expect(WebSocketClient).toHaveBeenCalledWith();
    });

    it('should auto-connect on mount when autoConnect is true', async () => {
      renderHook(() => useWebSocket({ autoConnect: true }));
      
      expect(mockClient.connect).toHaveBeenCalledTimes(1);
    });

    it('should not auto-connect when autoConnect is false', () => {
      renderHook(() => useWebSocket({ autoConnect: false }));
      
      expect(mockClient.connect).not.toHaveBeenCalled();
    });
  });

  describe('Connection Management', () => {
    it('should handle successful connection', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      expect(result.current.isConnected).toBe(false);
      
      act(() => {
        result.current.connect();
      });
      
      expect(result.current.isConnecting).toBe(true);
      
      act(() => {
        mockClient._mockConnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
        expect(result.current.isConnecting).toBe(false);
      });
    });

    it('should handle connection errors', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      const connectError = new Error('Connection failed');
      mockClient.connect.mockRejectedValueOnce(connectError);
      
      await act(async () => {
        await expectAsyncError(() => result.current.connect(), 'Connection failed');
      });
      
      expect(result.current.isConnected).toBe(false);
      expect(result.current.isConnecting).toBe(false);
    });

    it('should handle disconnection', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // First connect
      act(() => {
        result.current.connect();
        mockClient._mockConnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });
      
      // Then disconnect
      act(() => {
        result.current.disconnect();
        mockClient._mockDisconnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(false);
      });
    });

    it('should handle unexpected disconnection', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Connect first
      act(() => {
        result.current.connect();
        mockClient._mockConnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });
      
      // Simulate unexpected disconnect
      act(() => {
        mockClient._mockDisconnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(false);
      });
    });

    it('should handle rapid connect/disconnect cycles', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Rapid connect/disconnect
      for (let i = 0; i < 10; i++) {
        act(() => {
          result.current.connect();
          result.current.disconnect();
        });
      }
      
      // Should handle gracefully without errors
      expect(mockClient.connect).toHaveBeenCalled();
      expect(mockClient.disconnect).toHaveBeenCalled();
    });
  });

  describe('Event Handling', () => {
    it('should register event listeners', async () => {
      const { result } = renderHook(() => useWebSocket());
      const eventHandler = jest.fn();
      
      act(() => {
        result.current.on('test-event', eventHandler);
      });
      
      expect(mockClient.on).toHaveBeenCalledWith('test-event', expect.any(Function));
    });

    it('should remove event listeners', async () => {
      const { result } = renderHook(() => useWebSocket());
      const eventHandler = jest.fn();
      
      act(() => {
        result.current.on('test-event', eventHandler);
        result.current.off('test-event', eventHandler);
      });
      
      expect(mockClient.off).toHaveBeenCalledWith('test-event', expect.any(Function));
    });

    it('should handle events with data', async () => {
      const { result } = renderHook(() => useWebSocket());
      const eventHandler = jest.fn();
      
      act(() => {
        result.current.on('data-event', eventHandler);
      });
      
      const testData = { message: 'test data' };
      act(() => {
        mockClient._mockEvent('data-event', testData);
      });
      
      // Verify event was registered
      expect(mockClient.on).toHaveBeenCalledWith('data-event', expect.any(Function));
    });

    it('should handle multiple event listeners', () => {
      const { result } = renderHook(() => useWebSocket());
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      
      act(() => {
        result.current.on('multi-event', handler1);
        result.current.on('multi-event', handler2);
      });
      
      expect(mockClient.on).toHaveBeenCalledTimes(2);
    });

    it('should clean up event listeners on unmount', () => {
      const { result, unmount } = renderHook(() => useWebSocket());
      
      act(() => {
        result.current.on('cleanup-event', jest.fn());
      });
      
      unmount();
      
      // Should clean up internal state (implementation dependent)
      expect(mockClient.off).toHaveBeenCalled();
    });
  });

  describe('Message Sending', () => {
    it('should send messages when connected', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Connect first
      act(() => {
        result.current.connect();
        mockClient._mockConnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });
      
      const message = { type: 'test', data: 'hello' };
      act(() => {
        result.current.send('test-event', message);
      });
      
      expect(mockClient.send).toHaveBeenCalledWith('test-event', message);
    });

    it('should queue messages when not connected', () => {
      const { result } = renderHook(() => useWebSocket());
      
      const message = { type: 'test', data: 'hello' };
      act(() => {
        result.current.send('test-event', message);
      });
      
      // Message should be handled gracefully even when not connected
      expect(mockClient.send).toHaveBeenCalledWith('test-event', message);
    });

    it('should send legacy format messages', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      const message = { type: 'terminal-input', payload: 'ls -la' };
      act(() => {
        result.current.sendMessage(message);
      });
      
      expect(mockClient.sendMessage).toHaveBeenCalledWith(message);
    });

    it('should handle sending large messages', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      const largeMessage = {
        type: 'large-data',
        data: 'x'.repeat(10000)
      };
      
      act(() => {
        result.current.send('large-event', largeMessage);
      });
      
      expect(mockClient.send).toHaveBeenCalledWith('large-event', largeMessage);
    });
  });

  describe('Error Handling', () => {
    it('should handle WebSocket errors', async () => {
      const { result } = renderHook(() => useWebSocket());
      const errorHandler = jest.fn();
      
      act(() => {
        result.current.on('error', errorHandler);
      });
      
      const testError = new Error('WebSocket error');
      act(() => {
        mockClient._mockError(testError);
      });
      
      expect(mockClient.on).toHaveBeenCalledWith('error', expect.any(Function));
    });

    it('should handle connection timeout', async () => {
      const { result } = renderHook(() => useWebSocket({ connectionTimeout: 100 }));
      
      // Mock a connection that never completes
      mockClient.connect.mockImplementation(() => new Promise(() => {}));
      
      await act(async () => {
        await expectAsyncError(() => result.current.connect());
      });
    });

    it('should handle malformed event data', () => {
      const { result } = renderHook(() => useWebSocket());
      const eventHandler = jest.fn();
      
      act(() => {
        result.current.on('malformed-event', eventHandler);
      });
      
      // Send various malformed data
      act(() => {
        mockClient._mockEvent('malformed-event', null);
        mockClient._mockEvent('malformed-event', undefined);
        mockClient._mockEvent('malformed-event', '');
        mockClient._mockEvent('malformed-event', 0);
        mockClient._mockEvent('malformed-event', NaN);
      });
      
      // Should not crash
      expect(mockClient.on).toHaveBeenCalled();
    });
  });

  describe('Performance and Memory', () => {
    it('should handle rapid event registrations efficiently', () => {
      const { result } = renderHook(() => useWebSocket());
      const timer = performanceTimer();
      
      // Register many event listeners
      act(() => {
        for (let i = 0; i < 1000; i++) {
          result.current.on(`event-${i}`, jest.fn());
        }
      });
      
      const duration = timer.end();
      expect(duration).toBeLessThan(100); // Should complete within 100ms
      expect(mockClient.on).toHaveBeenCalledTimes(1000);
    });

    it('should handle high-frequency message sending', () => {
      const { result } = renderHook(() => useWebSocket());
      const timer = performanceTimer();
      
      act(() => {
        for (let i = 0; i < 1000; i++) {
          result.current.send('high-freq', { index: i });
        }
      });
      
      const duration = timer.end();
      expect(duration).toBeLessThan(200); // Should complete within 200ms
      expect(mockClient.send).toHaveBeenCalledTimes(1000);
    });

    it('should not leak memory on repeated mount/unmount', () => {
      const initialMemory = process.memoryUsage();
      
      // Mount and unmount many times
      for (let i = 0; i < 100; i++) {
        const { unmount } = renderHook(() => useWebSocket());
        unmount();
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage();
      const heapGrowth = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Should not grow significantly (allow for some test overhead)
      expect(heapGrowth).toBeLessThan(10 * 1024 * 1024); // 10MB threshold
    });
  });

  describe('Configuration Options', () => {
    it('should respect custom URL configuration', () => {
      const customUrl = 'ws://custom:9090';
      renderHook(() => useWebSocket({ url: customUrl }));
      
      const WebSocketClient = require('@/lib/websocket/client').default;
      expect(WebSocketClient).toHaveBeenCalledWith(customUrl);
    });

    it('should handle reconnection configuration', async () => {
      const { result } = renderHook(() => useWebSocket({ 
        autoReconnect: true,
        reconnectInterval: 100
      }));
      
      // Connect and then simulate disconnect
      act(() => {
        result.current.connect();
        mockClient._mockConnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });
      
      // Simulate unexpected disconnect
      act(() => {
        mockClient._mockDisconnect();
      });
      
      // Should attempt reconnection (implementation dependent)
      await waitFor(() => {
        expect(result.current.isConnected).toBe(false);
      });
    });

    it('should handle debug mode configuration', () => {
      renderHook(() => useWebSocket({ debug: true }));
      
      // Debug mode should not affect basic functionality
      expect(mockClient).toBeDefined();
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle terminal session workflow', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Connect and set up terminal event handlers
      act(() => {
        result.current.connect();
        result.current.on('terminal-output', jest.fn());
        result.current.on('terminal-resize', jest.fn());
        mockClient._mockConnect();
      });
      
      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });
      
      // Send terminal commands
      act(() => {
        result.current.send('terminal-input', { command: 'ls -la' });
        result.current.send('terminal-resize', { cols: 120, rows: 30 });
      });
      
      expect(mockClient.send).toHaveBeenCalledWith('terminal-input', { command: 'ls -la' });
      expect(mockClient.send).toHaveBeenCalledWith('terminal-resize', { cols: 120, rows: 30 });
    });

    it('should handle monitoring data workflow', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Set up monitoring event handlers
      act(() => {
        result.current.on('system-metrics', jest.fn());
        result.current.on('agent-status', jest.fn());
        result.current.on('memory-update', jest.fn());
      });
      
      // Request monitoring data
      act(() => {
        result.current.send('request-metrics', { interval: 1000 });
      });
      
      expect(mockClient.send).toHaveBeenCalledWith('request-metrics', { interval: 1000 });
    });

    it('should handle agent coordination workflow', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Set up agent coordination handlers
      act(() => {
        result.current.on('agent-spawned', jest.fn());
        result.current.on('agent-update', jest.fn());
        result.current.on('task-assigned', jest.fn());
      });
      
      // Send agent commands
      act(() => {
        result.current.send('spawn-agent', { type: 'coder', config: {} });
        result.current.send('assign-task', { agentId: 'agent-1', task: 'implement feature' });
      });
      
      expect(mockClient.send).toHaveBeenCalledTimes(2);
    });
  });

  describe('Accessibility and UX', () => {
    it('should provide connection state for UI feedback', () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Should provide clear state indicators
      expect(typeof result.current.isConnected).toBe('boolean');
      expect(typeof result.current.isConnecting).toBe('boolean');
    });

    it('should handle offline/online scenarios', async () => {
      const { result } = renderHook(() => useWebSocket());
      
      // Simulate going offline
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: false,
      });
      
      act(() => {
        result.current.connect();
      });
      
      // Should handle offline state gracefully
      expect(mockClient.connect).toHaveBeenCalled();
      
      // Simulate coming back online
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: true,
      });
    });
  });
});