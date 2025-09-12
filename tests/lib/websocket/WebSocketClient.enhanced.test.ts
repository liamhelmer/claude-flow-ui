import WebSocketClient, { wsClient } from '@/lib/websocket/client';
import { io } from 'socket.io-client';

// Mock socket.io-client
jest.mock('socket.io-client');

const mockIo = io as jest.MockedFunction<typeof io>;

describe('WebSocketClient Enhanced Tests', () => {
  let mockSocket: any;
  let client: WebSocketClient;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    
    mockSocket = {
      id: 'test-socket-id',
      connected: false,
      on: jest.fn(),
      off: jest.fn(),
      emit: jest.fn(),
      disconnect: jest.fn(),
      removeAllListeners: jest.fn(),
    };

    mockIo.mockReturnValue(mockSocket);
    client = new WebSocketClient('ws://localhost:11237');
  });

  afterEach(() => {
    jest.useRealTimers();
    client.disconnect();
  });

  describe('Constructor and Initialization', () => {
    it('should use default URL when none provided', () => {
      const defaultClient = new WebSocketClient();
      expect(defaultClient).toBeDefined();
    });

    it('should use custom URL when provided', () => {
      const customUrl = 'ws://custom-host:8080';
      const customClient = new WebSocketClient(customUrl);
      expect(customClient).toBeDefined();
    });

    it('should initialize with correct default state', () => {
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });
  });

  describe('Connection Management', () => {
    it('should handle successful connection', async () => {
      const connectPromise = client.connect();
      
      // Simulate successful connection
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      connectHandler?.();

      await connectPromise;
      
      expect(mockIo).toHaveBeenCalledWith('ws://localhost:11237', {
        transports: ['websocket', 'polling'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });
      expect(client.connected).toBe(true);
      expect(client.connecting).toBe(false);
    });

    it('should handle connection error', async () => {
      const connectPromise = client.connect();
      
      // Simulate connection error
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      const error = new Error('Connection failed');
      errorHandler?.(error);

      await expect(connectPromise).rejects.toThrow('Connection failed');
      expect(client.connecting).toBe(false);
    });

    it('should handle already connected state', async () => {
      mockSocket.connected = true;
      
      await client.connect();
      
      // Should not create new socket if already connected
      expect(mockIo).toHaveBeenCalledTimes(0);
    });

    it('should handle concurrent connection attempts', async () => {
      const connect1 = client.connect();
      const connect2 = client.connect();
      
      // Simulate successful connection
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      
      jest.advanceTimersByTime(150);
      connectHandler?.();

      await Promise.all([connect1, connect2]);
      
      expect(mockIo).toHaveBeenCalledTimes(1);
    });

    it('should handle disconnect with reason', () => {
      mockSocket.connected = true;
      
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      disconnectHandler?.('transport close');

      expect(client.connecting).toBe(false);
    });

    it('should properly disconnect and cleanup', () => {
      mockSocket.connected = true;
      
      client.disconnect();
      
      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client.connected).toBe(false);
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      mockSocket.connected = true;
    });

    it('should send messages when connected', () => {
      const testData = { test: 'data' };
      
      client.send('test-event', testData);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', testData);
    });

    it('should send WebSocket messages', () => {
      const message = {
        type: 'test',
        data: { content: 'test message' },
        timestamp: Date.now()
      };
      
      client.sendMessage(message);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should warn when sending while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockSocket.connected = false;
      
      client.send('test-event', {});
      
      expect(mockSocket.emit).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message');
      
      consoleSpy.mockRestore();
    });

    it('should handle malformed messages gracefully', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      client.sendMessage(null as any);
      client.sendMessage(undefined as any);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('message', null);
      expect(mockSocket.emit).toHaveBeenCalledWith('message', undefined);
      
      consoleSpy.mockRestore();
    });
  });

  describe('Event Handling', () => {
    it('should register event listeners', () => {
      const handler = jest.fn();
      
      client.on('test-event', handler);
      
      expect(client['listeners'].get('test-event')).toContain(handler);
    });

    it('should remove event listeners', () => {
      const handler = jest.fn();
      
      client.on('test-event', handler);
      client.off('test-event', handler);
      
      expect(client['listeners'].get('test-event')).not.toContain(handler);
    });

    it('should emit events to registered listeners', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      const testData = { test: 'data' };
      
      client.on('test-event', handler1);
      client.on('test-event', handler2);
      
      client['emit']('test-event', testData);
      
      expect(handler1).toHaveBeenCalledWith(testData);
      expect(handler2).toHaveBeenCalledWith(testData);
    });

    it('should warn about excessive listeners', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Add 11 listeners to trigger warning
      for (let i = 0; i < 11; i++) {
        client.on('test-event', jest.fn());
      }
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('MaxListenersExceededWarning')
      );
      
      consoleSpy.mockRestore();
    });

    it('should handle removing non-existent listeners', () => {
      const handler = jest.fn();
      
      expect(() => {
        client.off('non-existent-event', handler);
      }).not.toThrow();
    });

    it('should clear all listeners on disconnect', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      
      client.on('event1', handler1);
      client.on('event2', handler2);
      
      client.disconnect();
      
      expect(client['listeners'].size).toBe(0);
    });
  });

  describe('Message Routing', () => {
    beforeEach(async () => {
      await client.connect();
      mockSocket.connected = true;
    });

    it('should route terminal data messages', () => {
      const handler = jest.fn();
      client.on('terminal-data', handler);
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')?.[1];
      
      const testData = { sessionId: 'test', data: 'output' };
      terminalDataHandler?.(testData);
      
      expect(handler).toHaveBeenCalledWith(testData);
    });

    it('should route terminal resize messages', () => {
      const handler = jest.fn();
      client.on('terminal-resize', handler);
      
      const resizeHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'terminal-resize')?.[1];
      
      const testData = { sessionId: 'test', cols: 80, rows: 24 };
      resizeHandler?.(testData);
      
      expect(handler).toHaveBeenCalledWith(testData);
    });

    it('should route terminal config messages', () => {
      const handler = jest.fn();
      client.on('terminal-config', handler);
      
      const configHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')?.[1];
      
      const testData = { sessionId: 'test', cols: 80, rows: 24 };
      configHandler?.(testData);
      
      expect(handler).toHaveBeenCalledWith(testData);
    });

    it('should route terminal error messages', () => {
      const handler = jest.fn();
      client.on('terminal-error', handler);
      
      const errorHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'terminal-error')?.[1];
      
      const testData = { sessionId: 'test', error: 'Terminal error' };
      errorHandler?.(testData);
      
      expect(handler).toHaveBeenCalledWith(testData);
    });

    it('should route connection change messages', () => {
      const handler = jest.fn();
      client.on('connection-change', handler);
      
      const connectionHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'connection-change')?.[1];
      
      const testData = { connected: true };
      connectionHandler?.(testData);
      
      expect(handler).toHaveBeenCalledWith(testData);
    });

    it('should route session lifecycle messages', () => {
      const createdHandler = jest.fn();
      const destroyedHandler = jest.fn();
      
      client.on('session-created', createdHandler);
      client.on('session-destroyed', destroyedHandler);
      
      const sessionCreatedHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'session-created')?.[1];
      const sessionDestroyedHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'session-destroyed')?.[1];
      
      const createdData = { sessionId: 'new-session' };
      const destroyedData = { sessionId: 'old-session' };
      
      sessionCreatedHandler?.(createdData);
      sessionDestroyedHandler?.(destroyedData);
      
      expect(createdHandler).toHaveBeenCalledWith(createdData);
      expect(destroyedHandler).toHaveBeenCalledWith(destroyedData);
    });

    it('should route generic messages', () => {
      const handler = jest.fn();
      client.on('message', handler);
      
      const messageHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'message')?.[1];
      
      const testMessage = { type: 'test', data: 'message' };
      messageHandler?.(testMessage);
      
      expect(handler).toHaveBeenCalledWith(testMessage);
    });
  });

  describe('Test Environment Handling', () => {
    it('should handle test environment connection', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';
      
      const testClient = new WebSocketClient();
      const connectPromise = testClient.connect();
      
      jest.advanceTimersByTime(15);
      
      await connectPromise;
      
      expect(mockIo).not.toHaveBeenCalled();
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle socket creation failure', () => {
      mockIo.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });
      
      expect(async () => {
        await client.connect();
      }).rejects.toThrow();
    });

    it('should handle missing event handlers gracefully', () => {
      expect(() => {
        client['emit']('non-existent-event', {});
      }).not.toThrow();
    });

    it('should handle multiple disconnect calls', () => {
      mockSocket.connected = true;
      
      client.disconnect();
      client.disconnect(); // Second call should not throw
      
      expect(mockSocket.disconnect).toHaveBeenCalledTimes(1);
    });

    it('should handle connection timeout scenarios', async () => {
      const connectPromise = client.connect();
      
      // Simulate timeout by not calling connect handler
      jest.advanceTimersByTime(10000);
      
      // Then trigger error
      const errorHandler = mockSocket.on.mock.calls
        .find(call => call[0] === 'connect_error')?.[1];
      errorHandler?.(new Error('Timeout'));
      
      await expect(connectPromise).rejects.toThrow('Timeout');
    });

    it('should maintain state consistency during rapid operations', async () => {
      const operations = [];
      
      // Rapid connect/disconnect cycles
      for (let i = 0; i < 5; i++) {
        operations.push(client.connect());
        operations.push(Promise.resolve(client.disconnect()));
      }
      
      // Should not crash
      expect(() => {
        Promise.allSettled(operations);
      }).not.toThrow();
    });
  });

  describe('Memory Management', () => {
    it('should prevent memory leaks on repeated connections', async () => {
      for (let i = 0; i < 10; i++) {
        await client.connect();
        client.disconnect();
      }
      
      expect(client['listeners'].size).toBe(0);
    });

    it('should handle large numbers of event listeners efficiently', () => {
      const handlers = [];
      
      // Add many listeners
      for (let i = 0; i < 100; i++) {
        const handler = jest.fn();
        handlers.push(handler);
        client.on('test-event', handler);
      }
      
      // Remove all listeners
      handlers.forEach(handler => {
        client.off('test-event', handler);
      });
      
      expect(client['listeners'].get('test-event')?.length || 0).toBe(0);
    });
  });

  describe('Singleton Instance', () => {
    it('should export a singleton wsClient instance', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should maintain singleton state across imports', () => {
      const handler = jest.fn();
      wsClient.on('test-singleton', handler);
      
      expect(wsClient['listeners'].get('test-singleton')).toContain(handler);
    });
  });

  describe('Performance Characteristics', () => {
    it('should handle high-frequency message sending efficiently', () => {
      mockSocket.connected = true;
      const startTime = performance.now();
      
      // Send 1000 messages
      for (let i = 0; i < 1000; i++) {
        client.send('perf-test', { index: i });
      }
      
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(100); // Should complete in <100ms
      expect(mockSocket.emit).toHaveBeenCalledTimes(1000);
    });

    it('should handle high-frequency event emissions efficiently', () => {
      const handler = jest.fn();
      client.on('perf-event', handler);
      
      const startTime = performance.now();
      
      // Emit 1000 events
      for (let i = 0; i < 1000; i++) {
        client['emit']('perf-event', { index: i });
      }
      
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(100); // Should complete in <100ms
      expect(handler).toHaveBeenCalledTimes(1000);
    });
  });
});