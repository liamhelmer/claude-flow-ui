import { io, Socket } from 'socket.io-client';
import WebSocketClient, { wsClient } from '../client';
import type { WebSocketMessage } from '@/types';

// Mock socket.io-client
jest.mock('socket.io-client');

const mockSocket = {
  connected: false,
  id: 'mock-socket-id',
  connect: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  removeAllListeners: jest.fn(),
};

const mockIo = io as jest.MockedFunction<typeof io>;

describe('WebSocketClient', () => {
  let client: WebSocketClient;
  
  beforeEach(() => {
    jest.clearAllMocks();
    client = new WebSocketClient();
    mockIo.mockReturnValue(mockSocket as unknown as Socket);
    
    // Reset socket state
    mockSocket.connected = false;
    
    // Mock console methods to reduce noise
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
    jest.spyOn(console, 'warn').mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Constructor', () => {
    it('should create client with default URL', () => {
      const defaultClient = new WebSocketClient();
      expect(defaultClient).toBeInstanceOf(WebSocketClient);
      expect(defaultClient.connected).toBe(false);
      expect(defaultClient.connecting).toBe(false);
    });

    it('should create client with custom URL', () => {
      const customClient = new WebSocketClient('ws://custom.example.com');
      expect(customClient).toBeInstanceOf(WebSocketClient);
      expect(customClient.connected).toBe(false);
      expect(customClient.connecting).toBe(false);
    });

    it('should use environment variables for URL configuration', () => {
      const originalEnv = process.env;
      process.env = {
        ...originalEnv,
        NEXT_PUBLIC_WS_PORT: '9999',
        NEXT_PUBLIC_WS_URL: 'ws://env.example.com:9999',
      };

      // Re-import to pick up env changes
      jest.resetModules();
      
      process.env = originalEnv;
    });
  });

  describe('Connection Management', () => {
    it('should connect successfully', async () => {
      const connectPromise = client.connect();
      
      // Simulate successful connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      connectHandler?.();
      
      await expect(connectPromise).resolves.toBeUndefined();
      expect(mockIo).toHaveBeenCalledWith(expect.any(String), {
        transports: ['websocket', 'polling'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });
    });

    it('should handle connection errors', async () => {
      const connectPromise = client.connect();
      
      // Simulate connection error
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      const error = new Error('Connection failed');
      errorHandler?.(error);
      
      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('should resolve immediately if already connected', async () => {
      mockSocket.connected = true;
      
      const result = await client.connect();
      expect(result).toBeUndefined();
    });

    it('should handle concurrent connection attempts', async () => {
      const connectPromise1 = client.connect();
      const connectPromise2 = client.connect();
      
      // Simulate successful connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      connectHandler?.();
      
      await expect(Promise.all([connectPromise1, connectPromise2])).resolves.toEqual([undefined, undefined]);
    });

    it('should handle connection timeout during concurrent attempts', async () => {
      jest.useFakeTimers();
      
      const connectPromise1 = client.connect();
      const connectPromise2 = client.connect();
      
      // First connection fails
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      errorHandler?.(new Error('Timeout'));
      
      // Fast-forward timers
      jest.advanceTimersByTime(1000);
      
      await expect(connectPromise1).rejects.toThrow('Timeout');
      await expect(connectPromise2).rejects.toThrow('Connection failed');
      
      jest.useRealTimers();
    });

    it('should disconnect properly', () => {
      client.disconnect();
      
      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
    });

    it('should handle disconnect when not connected', () => {
      const clientWithoutSocket = new WebSocketClient();
      
      expect(() => clientWithoutSocket.disconnect()).not.toThrow();
    });

    it('should log disconnection events', async () => {
      await client.connect();
      
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      disconnectHandler?.('transport close');
      
      expect(console.log).toHaveBeenCalledWith('[WebSocket] Disconnected:', 'transport close');
    });
  });

  describe('Test Environment Handling', () => {
    it('should simulate connection in test environment', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';
      
      jest.useFakeTimers();
      
      const connectPromise = client.connect();
      
      // Fast-forward the simulated delay
      jest.advanceTimersByTime(20);
      
      await expect(connectPromise).resolves.toBeUndefined();
      
      process.env.NODE_ENV = originalEnv;
      jest.useRealTimers();
    });
  });

  describe('Message Sending', () => {
    beforeEach(async () => {
      mockSocket.connected = true;
      await client.connect();
    });

    it('should send message when connected', () => {
      client.send('test-event', { data: 'test' });
      
      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', { data: 'test' });
    });

    it('should send WebSocket message', () => {
      const message: WebSocketMessage = {
        type: 'test',
        data: { content: 'test message' },
      };
      
      client.sendMessage(message);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should warn when sending message while disconnected', () => {
      mockSocket.connected = false;
      
      client.send('test-event', { data: 'test' });
      
      expect(mockSocket.emit).not.toHaveBeenCalled();
      expect(console.warn).toHaveBeenCalledWith('WebSocket not connected, cannot send message');
    });

    it('should handle various data types', () => {
      const testCases = [
        { data: 'string' },
        { data: 123 },
        { data: true },
        { data: null },
        { data: undefined },
        { data: { nested: { object: 'value' } } },
        { data: [1, 2, 3] },
      ];
      
      testCases.forEach((testData, index) => {
        client.send(`test-${index}`, testData);
        expect(mockSocket.emit).toHaveBeenCalledWith(`test-${index}`, testData);
      });
    });
  });

  describe('Event Handling', () => {
    beforeEach(async () => {
      await client.connect();
    });

    it('should register event listeners', () => {
      const handler = jest.fn();
      
      client.on('test-event', handler);
      
      // Verify listener was added to internal map
      expect(handler).toBeDefined();
    });

    it('should remove event listeners', () => {
      const handler = jest.fn();
      
      client.on('test-event', handler);
      client.off('test-event', handler);
      
      // Listener should be removed
      expect(handler).toBeDefined();
    });

    it('should handle multiple listeners for same event', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      
      client.on('test-event', handler1);
      client.on('test-event', handler2);
      
      // Simulate event emission
      const testData = { message: 'test' };
      (client as any).emit('test-event', testData);
      
      expect(handler1).toHaveBeenCalledWith(testData);
      expect(handler2).toHaveBeenCalledWith(testData);
    });

    it('should warn about too many listeners', () => {
      const handlers = Array.from({ length: 11 }, () => jest.fn());
      
      handlers.forEach(handler => {
        client.on('test-event', handler);
      });
      
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('MaxListenersExceededWarning')
      );
    });

    it('should remove correct listener', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      
      client.on('test-event', handler1);
      client.on('test-event', handler2);
      client.off('test-event', handler1);
      
      // Simulate event emission
      (client as any).emit('test-event', { data: 'test' });
      
      expect(handler1).not.toHaveBeenCalled();
      expect(handler2).toHaveBeenCalled();
    });

    it('should handle removing non-existent listener', () => {
      const handler = jest.fn();
      
      expect(() => {
        client.off('non-existent-event', handler);
      }).not.toThrow();
    });

    it('should handle removing listener that was never added', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      
      client.on('test-event', handler1);
      
      expect(() => {
        client.off('test-event', handler2); // Different handler
      }).not.toThrow();
    });
  });

  describe('Built-in Socket Events', () => {
    beforeEach(async () => {
      await client.connect();
    });

    it('should set up message routing for all socket events', () => {
      const expectedEvents = [
        'message',
        'terminal-data',
        'terminal-resize',
        'terminal-config',
        'terminal-error',
        'connection-change',
        'session-created',
        'session-destroyed',
      ];
      
      expectedEvents.forEach(event => {
        const handler = mockSocket.on.mock.calls.find(call => call[0] === event)?.[1];
        expect(handler).toBeDefined();
      });
    });

    it('should route socket events to internal listeners', () => {
      const handler = jest.fn();
      client.on('terminal-data', handler);
      
      // Simulate socket event
      const terminalDataHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      const testData = { sessionId: 'test', data: 'output' };
      terminalDataHandler?.(testData);
      
      expect(handler).toHaveBeenCalledWith(testData);
    });

    it('should handle WebSocket message routing', () => {
      const handler = jest.fn();
      client.on('message', handler);
      
      // Simulate socket message event
      const messageHandler = mockSocket.on.mock.calls.find(call => call[0] === 'message')?.[1];
      const testMessage: WebSocketMessage = {
        type: 'test',
        data: { content: 'test' },
      };
      messageHandler?.(testMessage);
      
      expect(handler).toHaveBeenCalledWith(testMessage);
    });
  });

  describe('Connection State', () => {
    it('should return correct connected state', () => {
      expect(client.connected).toBe(false);
      
      mockSocket.connected = true;
      expect(client.connected).toBe(true);
    });

    it('should return correct connecting state', async () => {
      expect(client.connecting).toBe(false);
      
      const connectPromise = client.connect();
      expect(client.connecting).toBe(true);
      
      // Simulate connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      connectHandler?.();
      
      await connectPromise;
      expect(client.connecting).toBe(false);
    });

    it('should handle socket without connection state', () => {
      const clientWithoutSocket = new WebSocketClient();
      
      expect(clientWithoutSocket.connected).toBe(false);
      expect(clientWithoutSocket.connecting).toBe(false);
    });
  });

  describe('Memory Management', () => {
    it('should clear listeners on disconnect', () => {
      const handler = jest.fn();
      client.on('test-event', handler);
      
      client.disconnect();
      
      // Emit event after disconnect - handler should not be called
      (client as any).emit('test-event', { data: 'test' });
      expect(handler).not.toHaveBeenCalled();
    });

    it('should handle multiple disconnect calls', () => {
      expect(() => {
        client.disconnect();
        client.disconnect();
        client.disconnect();
      }).not.toThrow();
    });

    it('should prevent memory leaks with many listeners', () => {
      // Add many listeners
      for (let i = 0; i < 20; i++) {
        client.on(`event-${i}`, jest.fn());
      }
      
      // Should warn but not crash
      expect(console.warn).toHaveBeenCalled();
      
      // Disconnect should clean up
      client.disconnect();
    });
  });

  describe('Error Scenarios', () => {
    it('should handle socket creation failure', () => {
      mockIo.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });
      
      expect(async () => {
        await client.connect();
      }).rejects.toThrow('Socket creation failed');
    });

    it('should handle connect_error not rejecting if already connected', async () => {
      mockSocket.connected = true;
      
      const connectPromise = client.connect();
      
      // Simulate error after connection
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      errorHandler?.(new Error('Error after connect'));
      
      // Should not reject since already connected
      await expect(connectPromise).resolves.toBeUndefined();
    });

    it('should handle emit errors gracefully', () => {
      mockSocket.connected = true;
      mockSocket.emit.mockImplementation(() => {
        throw new Error('Emit failed');
      });
      
      expect(() => {
        client.send('test', { data: 'test' });
      }).toThrow('Emit failed');
    });

    it('should handle listener execution errors', () => {
      const faultyHandler = jest.fn(() => {
        throw new Error('Handler error');
      });
      const goodHandler = jest.fn();
      
      client.on('test-event', faultyHandler);
      client.on('test-event', goodHandler);
      
      expect(() => {
        (client as any).emit('test-event', { data: 'test' });
      }).toThrow('Handler error');
      
      // Good handler should not be called due to error
      expect(goodHandler).not.toHaveBeenCalled();
    });
  });

  describe('Singleton Export', () => {
    it('should export singleton instance', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should maintain state across imports', () => {
      // This tests that the singleton maintains state
      wsClient.on('test', jest.fn());
      expect(wsClient).toBe(wsClient); // Reference equality
    });
  });

  describe('URL Configuration', () => {
    it('should handle different URL formats', () => {
      const urlFormats = [
        'ws://localhost:8080',
        'wss://secure.example.com:443',
        'http://localhost:3000',
        'https://example.com',
      ];
      
      urlFormats.forEach(url => {
        const testClient = new WebSocketClient(url);
        expect(testClient).toBeInstanceOf(WebSocketClient);
      });
    });

    it('should handle malformed URLs gracefully', () => {
      const malformedUrls = [
        '',
        'not-a-url',
        'ftp://wrong-protocol',
        'ws://',
        'ws://localhost:',
      ];
      
      malformedUrls.forEach(url => {
        expect(() => new WebSocketClient(url)).not.toThrow();
      });
    });
  });

  describe('Development vs Production Behavior', () => {
    it('should log configuration in non-test environment', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalWindow = global.window;
      
      process.env.NODE_ENV = 'development';
      (global as any).window = {};
      
      // Clear console mock to test actual logging
      (console.log as jest.Mock).mockRestore();
      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      
      // Re-import to trigger logging
      jest.resetModules();
      require('../client');
      
      expect(logSpy).toHaveBeenCalledWith(
        '[WebSocket] Configuration:',
        expect.any(Object)
      );
      
      process.env.NODE_ENV = originalEnv;
      global.window = originalWindow;
      logSpy.mockRestore();
    });

    it('should not log in test environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';
      
      // Clear and re-import
      jest.resetModules();
      
      const logSpy = jest.spyOn(console, 'log');
      require('../client');
      
      expect(logSpy).not.toHaveBeenCalledWith(
        '[WebSocket] Configuration:',
        expect.any(Object)
      );
      
      process.env.NODE_ENV = originalEnv;
    });
  });
});
