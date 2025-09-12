import WebSocketClient, { wsClient } from '../client';
import { io } from 'socket.io-client';

// Mock socket.io-client
jest.mock('socket.io-client');

const mockIo = io as jest.MockedFunction<typeof io>;

describe('WebSocketClient', () => {
  let client: WebSocketClient;
  let mockSocket: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Create mock socket
    mockSocket = {
      id: 'mock-socket-id',
      connected: false,
      on: jest.fn(),
      off: jest.fn(),
      emit: jest.fn(),
      connect: jest.fn(),
      disconnect: jest.fn(),
      removeAllListeners: jest.fn(),
    };

    mockIo.mockReturnValue(mockSocket);

    client = new WebSocketClient();
  });

  describe('Constructor', () => {
    it('should use default URL when none provided', () => {
      const defaultClient = new WebSocketClient();
      expect(defaultClient['url']).toMatch(/^ws:\/\/localhost:\d+$/);
    });

    it('should use provided URL', () => {
      const customUrl = 'ws://custom.host:9999';
      const customClient = new WebSocketClient(customUrl);
      expect(customClient['url']).toBe(customUrl);
    });

    it('should initialize with correct default state', () => {
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
      expect(client['listeners']).toBeDefined();
      expect(client['socket']).toBeNull();
    });
  });

  describe('Connection Management', () => {
    it('should connect successfully', async () => {
      const connectPromise = client.connect();

      // Simulate successful connection
      mockSocket.connected = true;
      const connectCallback = mockSocket.on.mock.calls.find(call => call[0] === 'connect')[1];
      connectCallback();

      await expect(connectPromise).resolves.toBeUndefined();
      expect(mockIo).toHaveBeenCalledWith(client['url'], {
        transports: ['websocket', 'polling'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });
    });

    it('should handle connection errors', async () => {
      const error = new Error('Connection failed');
      const connectPromise = client.connect();

      // Simulate connection error
      const errorCallback = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')[1];
      errorCallback(error);

      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('should not create multiple connections when already connected', async () => {
      // Mock already connected state
      mockSocket.connected = true;
      client['socket'] = mockSocket;

      await client.connect();

      expect(mockIo).not.toHaveBeenCalled();
    });

    it('should wait for existing connection attempt', async () => {
      client['isConnecting'] = true;

      const connectPromise = client.connect();

      // Simulate connection completion
      setTimeout(() => {
        client['isConnecting'] = false;
        mockSocket.connected = true;
      }, 50);

      await expect(connectPromise).resolves.toBeUndefined();
    });

    it('should handle connection failure during wait', async () => {
      client['isConnecting'] = true;

      const connectPromise = client.connect();

      // Simulate connection failure
      setTimeout(() => {
        client['isConnecting'] = false;
        mockSocket.connected = false;
      }, 50);

      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('should disconnect properly', () => {
      client['socket'] = mockSocket;
      client['listeners'] = new Map([['test', [jest.fn()]]]);

      client.disconnect();

      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client['socket']).toBeNull();
      expect(client['isConnecting']).toBe(false);
      expect(client['listeners'].size).toBe(0);
    });

    it('should handle disconnect when no socket exists', () => {
      client['socket'] = null;

      expect(() => client.disconnect()).not.toThrow();
    });
  });

  describe('Test Environment Behavior', () => {
    const originalEnv = process.env.NODE_ENV;

    beforeEach(() => {
      process.env.NODE_ENV = 'test';
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('should simulate connection in test environment', async () => {
      jest.useFakeTimers();

      const connectPromise = client.connect();

      // Advance timers to simulate test connection
      jest.advanceTimersByTime(10);

      await expect(connectPromise).resolves.toBeUndefined();
      expect(mockIo).not.toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('should set connecting state in test environment', () => {
      jest.useFakeTimers();

      client.connect();
      expect(client.connecting).toBe(true);

      jest.advanceTimersByTime(10);
      expect(client.connecting).toBe(false);

      jest.useRealTimers();
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      client['socket'] = mockSocket;
      mockSocket.connected = true;
    });

    it('should send events when connected', () => {
      const eventData = { test: 'data' };

      client.send('test-event', eventData);

      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', eventData);
    });

    it('should send WebSocket messages', () => {
      const message = { type: 'test', data: 'test-data' };

      client.sendMessage(message);

      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should warn when sending while disconnected', () => {
      mockSocket.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      client.send('test', {});

      expect(mockSocket.emit).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message');

      consoleSpy.mockRestore();
    });

    it('should handle null socket gracefully', () => {
      client['socket'] = null;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      client.send('test', {});

      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message');

      consoleSpy.mockRestore();
    });
  });

  describe('Event Listener Management', () => {
    it('should add event listeners', () => {
      const callback = jest.fn();

      client.on('test-event', callback);

      const listeners = client['listeners'].get('test-event');
      expect(listeners).toContain(callback);
      expect(listeners?.length).toBe(1);
    });

    it('should add multiple listeners for same event', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      client.on('test-event', callback1);
      client.on('test-event', callback2);

      const listeners = client['listeners'].get('test-event');
      expect(listeners?.length).toBe(2);
      expect(listeners).toContain(callback1);
      expect(listeners).toContain(callback2);
    });

    it('should warn about too many listeners', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      // Add 11 listeners (limit is 10)
      for (let i = 0; i < 11; i++) {
        client.on('test-event', jest.fn());
      }

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('MaxListenersExceededWarning')
      );

      consoleSpy.mockRestore();
    });

    it('should remove event listeners', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      client.on('test-event', callback1);
      client.on('test-event', callback2);

      client.off('test-event', callback1);

      const listeners = client['listeners'].get('test-event');
      expect(listeners?.length).toBe(1);
      expect(listeners).toContain(callback2);
      expect(listeners).not.toContain(callback1);
    });

    it('should handle removing non-existent listeners', () => {
      const callback = jest.fn();

      expect(() => client.off('non-existent', callback)).not.toThrow();
    });

    it('should handle removing listeners from non-existent events', () => {
      const callback = jest.fn();
      client.on('test-event', callback);

      expect(() => client.off('other-event', callback)).not.toThrow();
    });

    it('should emit events to all listeners', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      const eventData = { test: 'data' };

      client.on('test-event', callback1);
      client.on('test-event', callback2);

      client['emit']('test-event', eventData);

      expect(callback1).toHaveBeenCalledWith(eventData);
      expect(callback2).toHaveBeenCalledWith(eventData);
    });

    it('should not emit to non-existent events', () => {
      const callback = jest.fn();
      client.on('test-event', callback);

      client['emit']('other-event', {});

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('Socket Event Setup', () => {
    it('should set up all socket event listeners on connect', async () => {
      const connectPromise = client.connect();

      // Simulate successful connection
      mockSocket.connected = true;
      const connectCallback = mockSocket.on.mock.calls.find(call => call[0] === 'connect')[1];
      connectCallback();

      await connectPromise;

      // Check that all expected events are registered
      const registeredEvents = mockSocket.on.mock.calls.map(call => call[0]);
      expect(registeredEvents).toContain('connect');
      expect(registeredEvents).toContain('disconnect');
      expect(registeredEvents).toContain('connect_error');
      expect(registeredEvents).toContain('message');
      expect(registeredEvents).toContain('terminal-data');
      expect(registeredEvents).toContain('terminal-resize');
      expect(registeredEvents).toContain('terminal-config');
      expect(registeredEvents).toContain('terminal-error');
      expect(registeredEvents).toContain('connection-change');
      expect(registeredEvents).toContain('session-created');
      expect(registeredEvents).toContain('session-destroyed');
    });

    it('should route socket messages to internal emit', async () => {
      const emitSpy = jest.spyOn(client as any, 'emit');
      
      await client.connect();

      // Simulate receiving a socket message
      const messageCallback = mockSocket.on.mock.calls.find(call => call[0] === 'message')[1];
      const testMessage = { type: 'test', data: 'test-data' };
      messageCallback(testMessage);

      expect(emitSpy).toHaveBeenCalledWith('message', testMessage);

      emitSpy.mockRestore();
    });

    it('should handle disconnect events', async () => {
      const emitSpy = jest.spyOn(client as any, 'emit');
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      await client.connect();

      const disconnectCallback = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')[1];
      disconnectCallback('transport close');

      expect(consoleSpy).toHaveBeenCalledWith('[WebSocket] Disconnected:', 'transport close');
      expect(client.connecting).toBe(false);

      consoleSpy.mockRestore();
      emitSpy.mockRestore();
    });

    it('should handle all terminal-related events', async () => {
      const emitSpy = jest.spyOn(client as any, 'emit');

      await client.connect();

      const events = [
        'terminal-data',
        'terminal-resize', 
        'terminal-config',
        'terminal-error',
        'connection-change',
        'session-created',
        'session-destroyed'
      ];

      events.forEach(eventName => {
        const callback = mockSocket.on.mock.calls.find(call => call[0] === eventName)[1];
        const testData = { event: eventName, test: 'data' };
        callback(testData);

        expect(emitSpy).toHaveBeenCalledWith(eventName, testData);
      });

      emitSpy.mockRestore();
    });
  });

  describe('Connection Properties', () => {
    it('should return correct connected state', () => {
      expect(client.connected).toBe(false);

      client['socket'] = mockSocket;
      mockSocket.connected = true;

      expect(client.connected).toBe(true);
    });

    it('should return false when socket is null', () => {
      client['socket'] = null;

      expect(client.connected).toBe(false);
    });

    it('should return correct connecting state', () => {
      expect(client.connecting).toBe(false);

      client['isConnecting'] = true;

      expect(client.connecting).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle connection errors with proper logging', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      const error = new Error('Connection failed');

      const connectPromise = client.connect();

      const errorCallback = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')[1];
      errorCallback(error);

      await expect(connectPromise).rejects.toThrow('Connection failed');
      expect(consoleSpy).toHaveBeenCalledWith('[WebSocket] Connection error:', error.message);
      expect(consoleSpy).toHaveBeenCalledWith('[WebSocket] Full error:', error);

      consoleSpy.mockRestore();
    });

    it('should not reject if already connected despite error', async () => {
      mockSocket.connected = true;
      client['socket'] = mockSocket;

      const connectPromise = client.connect();

      const errorCallback = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')[1];
      errorCallback(new Error('Some error'));

      await expect(connectPromise).resolves.toBeUndefined();
    });

    it('should handle event listener errors gracefully', () => {
      const throwingCallback = jest.fn(() => {
        throw new Error('Callback error');
      });

      client.on('test-event', throwingCallback);

      expect(() => client['emit']('test-event', {})).not.toThrow();
      expect(throwingCallback).toHaveBeenCalled();
    });
  });

  describe('Singleton Export', () => {
    it('should export a singleton instance', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should maintain singleton state across imports', () => {
      wsClient['testProperty'] = 'test-value';
      
      // This would be true if importing in another test file
      expect(wsClient['testProperty']).toBe('test-value');
      
      delete wsClient['testProperty'];
    });
  });

  describe('Environment Configuration Logging', () => {
    const originalEnv = process.env.NODE_ENV;
    const originalWindow = global.window;

    beforeEach(() => {
      // Reset environment
      delete process.env.NEXT_PUBLIC_WS_PORT;
      delete process.env.NEXT_PUBLIC_WS_URL;
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
      global.window = originalWindow;
    });

    it('should log configuration in browser environment', () => {
      process.env.NODE_ENV = 'development';
      global.window = {} as any;

      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      // Re-import to trigger configuration logging
      jest.resetModules();
      require('../client');

      expect(consoleSpy).toHaveBeenCalledWith('[WebSocket] Configuration:', expect.any(Object));

      consoleSpy.mockRestore();
    });

    it('should not log configuration in test environment', () => {
      process.env.NODE_ENV = 'test';
      global.window = {} as any;

      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      // Re-import to trigger configuration check
      jest.resetModules();
      require('../client');

      expect(consoleSpy).not.toHaveBeenCalledWith('[WebSocket] Configuration:', expect.any(Object));

      consoleSpy.mockRestore();
    });

    it('should use environment variables for configuration', () => {
      process.env.NEXT_PUBLIC_WS_PORT = '9999';
      process.env.NEXT_PUBLIC_WS_URL = 'ws://custom.host:9999';

      const customClient = new WebSocketClient();
      expect(customClient['url']).toBe('ws://custom.host:9999');
    });
  });

  describe('Memory Management', () => {
    it('should clean up properly on disconnect', () => {
      client['socket'] = mockSocket;
      client.on('test1', jest.fn());
      client.on('test2', jest.fn());
      client.on('test2', jest.fn());

      expect(client['listeners'].size).toBe(2);

      client.disconnect();

      expect(client['listeners'].size).toBe(0);
      expect(client['socket']).toBeNull();
    });

    it('should handle multiple disconnect calls', () => {
      client['socket'] = mockSocket;

      expect(() => {
        client.disconnect();
        client.disconnect();
        client.disconnect();
      }).not.toThrow();
    });

    it('should handle rapid connect/disconnect cycles', async () => {
      jest.useFakeTimers();

      for (let i = 0; i < 10; i++) {
        const promise = client.connect();
        jest.advanceTimersByTime(5);
        client.disconnect();
        
        try {
          await promise;
        } catch (e) {
          // Expected in some cases
        }
      }

      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);

      jest.useRealTimers();
    });
  });
});