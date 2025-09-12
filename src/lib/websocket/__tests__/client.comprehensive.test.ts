import WebSocketClient, { wsClient } from '../client';
import { io, Socket } from 'socket.io-client';
import type { WebSocketMessage } from '@/types';

// Mock socket.io-client
jest.mock('socket.io-client');

const mockIo = io as jest.MockedFunction<typeof io>;

describe('WebSocketClient - Comprehensive Test Suite', () => {
  let client: WebSocketClient;
  let mockSocket: jest.Mocked<Socket>;
  let originalConsole: any;
  let originalWindow: any;
  let originalProcessEnv: any;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.clearAllTimers();
    
    // Mock console to reduce noise
    originalConsole = {
      log: console.log,
      warn: console.warn,
      error: console.error,
    };
    console.log = jest.fn();
    console.warn = jest.fn();
    console.error = jest.fn();
    
    // Store original window and process.env
    originalWindow = global.window;
    originalProcessEnv = { ...process.env };
    
    // Mock socket instance
    mockSocket = {
      id: 'socket-123',
      connected: false,
      connect: jest.fn(),
      disconnect: jest.fn(),
      emit: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      removeAllListeners: jest.fn(),
    } as any;
    
    mockIo.mockReturnValue(mockSocket);
    
    // Mock window.location - handle existing window object
    if (typeof global.window !== 'undefined') {
      global.window = {
        ...global.window,
        location: {
          ...global.window.location,
          port: '3000',
        },
      };
    } else {
      Object.defineProperty(global, 'window', {
        value: {
          location: {
            port: '3000',
          },
        },
        writable: true,
        configurable: true,
      });
    }
    
    client = new WebSocketClient();
    
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.clearAllMocks();
    
    // Restore mocks
    console.log = originalConsole.log;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
    global.window = originalWindow;
    process.env = originalProcessEnv;
  });

  describe('Port Calculation and URL Construction', () => {
    it('should calculate WebSocket port from window location', () => {
      global.window = {
        ...global.window,
        location: { port: '3000' },
      };
      
      const testClient = new WebSocketClient();
      
      // Should use port 3001 (3000 + 1)
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('WebSocket port: 3001')
      );
    });

    it('should use environment variable when available', () => {
      process.env.NEXT_PUBLIC_WS_PORT = '8080';
      
      const testClient = new WebSocketClient();
      
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('8080')
      );
    });

    it('should fall back to default port', () => {
      global.window = {
        ...global.window,
        location: { port: '' },
      };
      
      delete process.env.NEXT_PUBLIC_WS_PORT;
      
      const testClient = new WebSocketClient();
      
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('11236')
      );
    });

    it('should use provided URL over calculated one', () => {
      const customUrl = 'ws://custom.server:9999';
      const testClient = new WebSocketClient(customUrl);
      
      expect(console.log).toHaveBeenCalledWith(
        'Using provided URL:',
        customUrl
      );
    });

    it('should handle non-browser environments', () => {
      Object.defineProperty(global, 'window', {
        value: undefined,
        writable: true,
      });
      
      process.env.NEXT_PUBLIC_WS_PORT = '5000';
      
      const testClient = new WebSocketClient();
      
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('5000')
      );
    });
  });

  describe('Connection Management', () => {
    it('should establish connection successfully', async () => {
      const connectPromise = client.connect();
      
      // Simulate successful connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      
      act(() => {
        connectHandler?.();
      });
      
      await connectPromise;
      
      expect(mockIo).toHaveBeenCalledWith(
        expect.stringContaining('localhost:3001'),
        expect.objectContaining({
          transports: ['websocket', 'polling'],
          autoConnect: false,
          reconnection: true,
          reconnectionAttempts: 5,
          reconnectionDelay: 1000,
        })
      );
      
      expect(mockSocket.connect).toHaveBeenCalled();
    });

    it('should handle connection errors', async () => {
      const connectPromise = client.connect();
      
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      const error = new Error('Connection failed');
      
      act(() => {
        errorHandler?.(error);
      });
      
      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('should setup event listeners before connecting', async () => {
      await client.connect();
      
      // Verify all event listeners are registered
      const eventTypes = mockSocket.on.mock.calls.map(call => call[0]);
      
      expect(eventTypes).toContain('message');
      expect(eventTypes).toContain('terminal-data');
      expect(eventTypes).toContain('terminal-resize');
      expect(eventTypes).toContain('terminal-config');
      expect(eventTypes).toContain('terminal-error');
      expect(eventTypes).toContain('connection-change');
      expect(eventTypes).toContain('session-created');
      expect(eventTypes).toContain('session-destroyed');
      expect(eventTypes).toContain('connect');
      expect(eventTypes).toContain('disconnect');
      expect(eventTypes).toContain('connect_error');
    });

    it('should handle connection timeout', async () => {
      const connectPromise = client.connect();
      
      // Fast-forward past timeout
      act(() => {
        jest.advanceTimersByTime(6000);
      });
      
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('Connection timeout after 5 seconds')
      );
    });

    it('should prevent duplicate connections', async () => {
      mockSocket.connected = true;
      
      const result = await client.connect();
      
      expect(mockSocket.connect).not.toHaveBeenCalled();
    });

    it('should handle concurrent connection attempts', async () => {
      const promise1 = client.connect();
      const promise2 = client.connect();
      
      // Simulate connection success
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      
      act(() => {
        connectHandler?.();
      });
      
      await Promise.all([promise1, promise2]);
      
      expect(mockSocket.connect).toHaveBeenCalledTimes(1);
    });

    it('should handle waiting for existing connection attempt', async () => {
      // Start first connection but don't resolve
      const promise1 = client.connect();
      
      // Start second connection
      const promise2 = client.connect();
      
      // First connection fails
      act(() => {
        Object.defineProperty(client, 'isConnecting', { value: false });
      });
      
      await expect(promise2).rejects.toThrow('Connection failed');
    });
  });

  describe('Test Environment Handling', () => {
    it('should simulate connection in test environment', async () => {
      process.env.NODE_ENV = 'test';
      
      const testClient = new WebSocketClient();
      const connectPromise = testClient.connect();
      
      act(() => {
        jest.advanceTimersByTime(20);
      });
      
      await expect(connectPromise).resolves.toBeUndefined();
      expect(mockIo).not.toHaveBeenCalled();
    });

    it('should handle test environment edge cases', async () => {
      process.env.NODE_ENV = 'test';
      
      const testClient = new WebSocketClient();
      
      // Multiple rapid connections in test mode
      const promises = [
        testClient.connect(),
        testClient.connect(),
        testClient.connect(),
      ];
      
      act(() => {
        jest.advanceTimersByTime(50);
      });
      
      await Promise.all(promises);
      
      expect(mockIo).not.toHaveBeenCalled();
    });
  });

  describe('Message Handling', () => {
    beforeEach(async () => {
      mockSocket.connected = true;
      await client.connect();
    });

    it('should send messages when connected', () => {
      client.send('test-event', { data: 'test' });
      
      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', { data: 'test' });
    });

    it('should send WebSocket messages', () => {
      const message: WebSocketMessage = {
        type: 'terminal-data',
        payload: { sessionId: 'test', data: 'command' },
        timestamp: Date.now(),
      };
      
      client.sendMessage(message);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should warn when sending while disconnected', () => {
      mockSocket.connected = false;
      Object.defineProperty(client, 'connected', { value: false });
      
      client.send('test-event', { data: 'test' });
      
      expect(mockSocket.emit).not.toHaveBeenCalled();
      expect(console.warn).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send message'
      );
    });

    it('should handle incoming messages correctly', async () => {
      const callback = jest.fn();
      client.on('terminal-data', callback);
      
      const messageHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      const testData = { sessionId: 'test', data: 'output' };
      
      act(() => {
        messageHandler?.(testData);
      });
      
      expect(callback).toHaveBeenCalledWith(testData);
    });

    it('should handle multiple message types', async () => {
      const callbacks = {
        'terminal-data': jest.fn(),
        'terminal-config': jest.fn(),
        'session-created': jest.fn(),
      };
      
      Object.entries(callbacks).forEach(([event, callback]) => {
        client.on(event, callback);
      });
      
      // Simulate different message types
      const handlers = mockSocket.on.mock.calls.reduce((acc, [event, handler]) => {
        acc[event] = handler;
        return acc;
      }, {} as Record<string, Function>);
      
      act(() => {
        handlers['terminal-data']?.({ data: 'test' });
        handlers['terminal-config']?.({ cols: 80, rows: 24 });
        handlers['session-created']?.({ sessionId: 'new' });
      });
      
      expect(callbacks['terminal-data']).toHaveBeenCalledWith({ data: 'test' });
      expect(callbacks['terminal-config']).toHaveBeenCalledWith({ cols: 80, rows: 24 });
      expect(callbacks['session-created']).toHaveBeenCalledWith({ sessionId: 'new' });
    });
  });

  describe('Event Listener Management', () => {
    it('should add event listeners correctly', () => {
      const callback = jest.fn();
      
      client.on('test-event', callback);
      
      expect(client['listeners'].get('test-event')).toContain(callback);
    });

    it('should remove event listeners correctly', () => {
      const callback = jest.fn();
      
      client.on('test-event', callback);
      client.off('test-event', callback);
      
      const listeners = client['listeners'].get('test-event') || [];
      expect(listeners).not.toContain(callback);
    });

    it('should warn about too many listeners', () => {
      const callbacks = Array.from({ length: 11 }, () => jest.fn());
      
      callbacks.forEach(callback => {
        client.on('test-event', callback);
      });
      
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('MaxListenersExceededWarning')
      );
    });

    it('should handle removing non-existent listeners', () => {
      const callback = jest.fn();
      
      expect(() => {
        client.off('non-existent', callback);
      }).not.toThrow();
    });

    it('should handle multiple listeners for same event', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      const callback3 = jest.fn();
      
      client.on('test-event', callback1);
      client.on('test-event', callback2);
      client.on('test-event', callback3);
      
      client['emit']('test-event', { data: 'test' });
      
      expect(callback1).toHaveBeenCalledWith({ data: 'test' });
      expect(callback2).toHaveBeenCalledWith({ data: 'test' });
      expect(callback3).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should handle listener exceptions gracefully', () => {
      const throwingCallback = jest.fn(() => {
        throw new Error('Listener error');
      });
      const normalCallback = jest.fn();
      
      client.on('test-event', throwingCallback);
      client.on('test-event', normalCallback);
      
      expect(() => {
        client['emit']('test-event', { data: 'test' });
      }).not.toThrow();
      
      expect(throwingCallback).toHaveBeenCalled();
      expect(normalCallback).toHaveBeenCalled();
    });
  });

  describe('Disconnect and Cleanup', () => {
    beforeEach(async () => {
      mockSocket.connected = true;
      await client.connect();
    });

    it('should disconnect properly', () => {
      client.disconnect();
      
      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client.connected).toBe(false);
    });

    it('should clear all listeners on disconnect', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      
      client.on('event1', callback1);
      client.on('event2', callback2);
      
      client.disconnect();
      
      expect(client['listeners'].size).toBe(0);
    });

    it('should handle disconnect events', async () => {
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      
      act(() => {
        disconnectHandler?.('transport close');
      });
      
      expect(console.log).toHaveBeenCalledWith(
        '[WebSocket] Disconnected:',
        'transport close'
      );
    });

    it('should handle multiple disconnects safely', () => {
      client.disconnect();
      client.disconnect();
      client.disconnect();
      
      expect(mockSocket.disconnect).toHaveBeenCalledTimes(1);
    });

    it('should reset connecting state on disconnect', () => {
      Object.defineProperty(client, 'isConnecting', { value: true, writable: true });
      
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      
      act(() => {
        disconnectHandler?.('manual disconnect');
      });
      
      expect(client.connecting).toBe(false);
    });
  });

  describe('Connection State Properties', () => {
    it('should return correct connected state', () => {
      mockSocket.connected = true;
      Object.defineProperty(client, 'socket', { value: mockSocket });
      
      expect(client.connected).toBe(true);
      
      mockSocket.connected = false;
      expect(client.connected).toBe(false);
    });

    it('should return false when socket is null', () => {
      Object.defineProperty(client, 'socket', { value: null });
      
      expect(client.connected).toBe(false);
    });

    it('should return correct connecting state', () => {
      Object.defineProperty(client, 'isConnecting', { value: true });
      
      expect(client.connecting).toBe(true);
      
      Object.defineProperty(client, 'isConnecting', { value: false });
      
      expect(client.connecting).toBe(false);
    });
  });

  describe('Error Scenarios', () => {
    it('should handle socket creation errors', () => {
      mockIo.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });
      
      expect(async () => {
        const errorClient = new WebSocketClient();
        await errorClient.connect();
      }).not.toThrow(); // Constructor shouldn't throw
    });

    it('should handle socket.io connection errors', async () => {
      const connectPromise = client.connect();
      
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      const error = new Error('Network error');
      
      act(() => {
        errorHandler?.(error);
      });
      
      await expect(connectPromise).rejects.toThrow('Network error');
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Connection error'),
        'Network error',
        expect.any(String)
      );
    });

    it('should handle errors after successful connection', async () => {
      mockSocket.connected = true;
      await client.connect();
      
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      
      act(() => {
        errorHandler?.(new Error('Post-connection error'));
      });
      
      // Should not affect already connected socket
      expect(client.connected).toBe(true);
    });

    it('should handle malformed incoming messages', async () => {
      mockSocket.connected = true;
      await client.connect();
      
      const callback = jest.fn();
      client.on('terminal-data', callback);
      
      const messageHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      
      // Send malformed data
      act(() => {
        messageHandler?.(null);
        messageHandler?.(undefined);
        messageHandler?.('string instead of object');
      });
      
      expect(callback).toHaveBeenCalledTimes(3);
      expect(callback).toHaveBeenCalledWith(null);
      expect(callback).toHaveBeenCalledWith(undefined);
      expect(callback).toHaveBeenCalledWith('string instead of object');
    });
  });

  describe('Performance and Memory Management', () => {
    it('should handle high-frequency message sending', async () => {
      mockSocket.connected = true;
      await client.connect();
      
      // Send many messages rapidly
      for (let i = 0; i < 1000; i++) {
        client.send('bulk-message', { index: i });
      }
      
      expect(mockSocket.emit).toHaveBeenCalledTimes(1000);
    });

    it('should handle many event listeners efficiently', () => {
      const callbacks = Array.from({ length: 100 }, () => jest.fn());
      
      callbacks.forEach((callback, index) => {
        client.on(`event-${index}`, callback);
      });
      
      expect(client['listeners'].size).toBe(100);
      
      // Remove all
      callbacks.forEach((callback, index) => {
        client.off(`event-${index}`, callback);
      });
      
      expect(client['listeners'].size).toBe(100); // Empty arrays still exist
    });

    it('should clean up properly on multiple connects/disconnects', async () => {
      for (let i = 0; i < 10; i++) {
        mockSocket.connected = true;
        await client.connect();
        
        client.on(`event-${i}`, jest.fn());
        
        client.disconnect();
        
        expect(client['listeners'].size).toBe(0);
      }
      
      expect(mockSocket.removeAllListeners).toHaveBeenCalledTimes(10);
    });

    it('should handle concurrent event emissions', async () => {
      mockSocket.connected = true;
      await client.connect();
      
      const callbacks = Array.from({ length: 10 }, () => jest.fn());
      
      callbacks.forEach(callback => {
        client.on('concurrent-event', callback);
      });
      
      // Emit multiple events concurrently
      const emissions = Array.from({ length: 5 }, (_, i) => 
        () => client['emit']('concurrent-event', { data: i })
      );
      
      emissions.forEach(emit => emit());
      
      callbacks.forEach(callback => {
        expect(callback).toHaveBeenCalledTimes(5);
      });
    });
  });

  describe('Integration with Singleton Instance', () => {
    it('should export a singleton instance', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should maintain singleton state across imports', () => {
      const callback = jest.fn();
      wsClient.on('singleton-test', callback);
      
      wsClient['emit']('singleton-test', { data: 'test' });
      
      expect(callback).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should handle singleton operations safely', () => {
      expect(() => {
        wsClient.connect();
        wsClient.send('test', {});
        wsClient.disconnect();
      }).not.toThrow();
    });
  });

  describe('Real-world Usage Patterns', () => {
    it('should handle terminal session workflow', async () => {
      mockSocket.connected = true;
      await client.connect();
      
      const sessionCallbacks = {
        config: jest.fn(),
        data: jest.fn(),
        error: jest.fn(),
      };
      
      client.on('terminal-config', sessionCallbacks.config);
      client.on('terminal-data', sessionCallbacks.data);
      client.on('terminal-error', sessionCallbacks.error);
      
      // Simulate terminal workflow
      const handlers = mockSocket.on.mock.calls.reduce((acc, [event, handler]) => {
        acc[event] = handler;
        return acc;
      }, {} as Record<string, Function>);
      
      act(() => {
        // Terminal configuration
        handlers['terminal-config']?.({ sessionId: 'term1', cols: 80, rows: 24 });
        
        // Terminal data
        handlers['terminal-data']?.({ sessionId: 'term1', data: 'user@host:~$ ' });
        handlers['terminal-data']?.({ sessionId: 'term1', data: 'ls\\r\\n' });
        handlers['terminal-data']?.({ sessionId: 'term1', data: 'file1.txt  file2.txt\\r\\n' });
        
        // Terminal error
        handlers['terminal-error']?.({ sessionId: 'term1', error: 'Command not found' });
      });
      
      expect(sessionCallbacks.config).toHaveBeenCalledWith({ sessionId: 'term1', cols: 80, rows: 24 });
      expect(sessionCallbacks.data).toHaveBeenCalledTimes(3);
      expect(sessionCallbacks.error).toHaveBeenCalledWith({ sessionId: 'term1', error: 'Command not found' });
      
      // Send commands
      client.send('data', { sessionId: 'term1', data: 'pwd\\r' });
      client.send('resize', { sessionId: 'term1', cols: 100, rows: 30 });
      
      expect(mockSocket.emit).toHaveBeenCalledWith('data', { sessionId: 'term1', data: 'pwd\\r' });
      expect(mockSocket.emit).toHaveBeenCalledWith('resize', { sessionId: 'term1', cols: 100, rows: 30 });
    });

    it('should handle reconnection scenario', async () => {
      // Initial connection
      mockSocket.connected = true;
      await client.connect();
      
      const callback = jest.fn();
      client.on('test-event', callback);
      
      // Simulate disconnect
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      
      act(() => {
        mockSocket.connected = false;
        disconnectHandler?.('transport error');
      });
      
      expect(client.connected).toBe(false);
      
      // Reconnect
      mockSocket.connected = true;
      await client.connect();
      
      // Should still have listeners
      client['emit']('test-event', { data: 'after reconnect' });
      expect(callback).toHaveBeenCalledWith({ data: 'after reconnect' });
    });
  });
});

function act(fn: () => void) {
  fn();
}