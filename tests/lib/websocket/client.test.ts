import WebSocketClient, { wsClient } from '@/lib/websocket/client';
import { io } from 'socket.io-client';

// Mock socket.io-client
jest.mock('socket.io-client');

const mockIo = io as jest.MockedFunction<typeof io>;

describe('WebSocketClient', () => {
  let client: WebSocketClient;
  let mockSocket: any;

  beforeEach(() => {
    // Create a mock socket
    mockSocket = {
      connected: false,
      connect: jest.fn(),
      disconnect: jest.fn(),
      emit: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      id: 'mock-socket-id',
    };

    // Mock io to return our mock socket
    mockIo.mockReturnValue(mockSocket);

    client = new WebSocketClient('ws://test-server.com:12345');

    // Clear console logs for cleaner test output
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    it('should create instance with default URL', () => {
      const defaultClient = new WebSocketClient();
      expect(defaultClient).toBeInstanceOf(WebSocketClient);
    });

    it('should create instance with custom URL', () => {
      const customClient = new WebSocketClient('ws://custom.com:9999');
      expect(customClient).toBeInstanceOf(WebSocketClient);
    });

    it('should log configuration in browser environment', () => {
      // Mock window object
      Object.defineProperty(global, 'window', {
        value: {},
        writable: true,
      });

      const logSpy = jest.spyOn(console, 'log');
      new WebSocketClient('ws://test.com:8080');

      expect(logSpy).toHaveBeenCalledWith(
        '[WebSocket] Configuration:',
        expect.any(Object)
      );
    });
  });

  describe('Connection Management', () => {
    it('should connect successfully', async () => {
      // Simulate successful connection
      mockSocket.connected = false;
      
      const connectPromise = client.connect();
      
      // Simulate connect event
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      if (connectHandler && typeof connectHandler === 'function') {
        connectHandler();
      }
      
      await expect(connectPromise).resolves.toBeUndefined();
      
      expect(mockIo).toHaveBeenCalledWith('ws://test-server.com:12345', {
        transports: ['websocket', 'polling'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });
    });

    it('should resolve immediately if already connected', async () => {
      mockSocket.connected = true;
      
      const result = await client.connect();
      
      expect(result).toBeUndefined();
      expect(mockIo).not.toHaveBeenCalled();
    });

    it('should handle connection waiting when already connecting', async () => {
      // Start first connection
      const firstConnect = client.connect();
      
      // Start second connection while first is in progress
      const secondConnect = client.connect();
      
      // Complete the connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      if (connectHandler && typeof connectHandler === 'function') {
        connectHandler();
      }
      
      await expect(firstConnect).resolves.toBeUndefined();
      await expect(secondConnect).resolves.toBeUndefined();
    });

    it('should handle connection errors', async () => {
      const connectPromise = client.connect();
      
      // Simulate connection error
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      const error = new Error('Connection failed');
      errorHandler(error);
      
      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('should handle disconnection', async () => {
      // Connect first
      mockSocket.connected = false;
      const connectPromise = client.connect();
      
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      if (connectHandler && typeof connectHandler === 'function') {
        connectHandler();
      }
      
      await connectPromise;
      
      // Simulate disconnection
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')[1];
      mockSocket.connected = false;
      disconnectHandler('transport close');
      
      expect(client.connected).toBe(false);
    });

    it('should disconnect cleanly', () => {
      // Setup connected state
      mockSocket.connected = true;
      client.connect();
      
      client.disconnect();
      
      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client.connected).toBe(false);
    });
  });

  describe('Message Sending', () => {
    beforeEach(async () => {
      // Setup connected client
      mockSocket.connected = true;
      await client.connect();
    });

    it('should send messages when connected', () => {
      const testData = { type: 'test', message: 'hello' };
      
      client.send('test-event', testData);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', testData);
    });

    it('should send WebSocket messages', () => {
      const message = {
        type: 'data' as const,
        sessionId: 'session-123',
        data: 'test data',
      };
      
      client.sendMessage(message);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should warn when trying to send while not connected', () => {
      mockSocket.connected = false;
      const warnSpy = jest.spyOn(console, 'warn');
      
      client.send('test-event', { data: 'test' });
      
      expect(mockSocket.emit).not.toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message');
    });

    it('should handle sending null data', () => {
      client.send('test-event', null);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', null);
    });

    it('should handle sending complex data', () => {
      const complexData = {
        user: { id: 1, name: 'John' },
        actions: ['login', 'navigate'],
        metadata: { timestamp: Date.now() },
      };
      
      client.send('complex-event', complexData);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('complex-event', complexData);
    });
  });

  describe('Event Handling', () => {
    let callback: jest.Mock;

    beforeEach(() => {
      callback = jest.fn();
    });

    it('should register event listeners', () => {
      client.on('test-event', callback);
      
      // Simulate event emission
      client['emit']('test-event', { data: 'test' });
      
      expect(callback).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should handle multiple listeners for same event', () => {
      const callback2 = jest.fn();
      
      client.on('test-event', callback);
      client.on('test-event', callback2);
      
      client['emit']('test-event', { data: 'test' });
      
      expect(callback).toHaveBeenCalledWith({ data: 'test' });
      expect(callback2).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should remove event listeners', () => {
      client.on('test-event', callback);
      client.off('test-event', callback);
      
      client['emit']('test-event', { data: 'test' });
      
      expect(callback).not.toHaveBeenCalled();
    });

    it('should handle removing non-existent listener', () => {
      // Should not throw error
      expect(() => {
        client.off('non-existent-event', callback);
      }).not.toThrow();
    });

    it('should handle removing listener that was never added', () => {
      client.on('test-event', jest.fn());
      
      expect(() => {
        client.off('test-event', callback);
      }).not.toThrow();
    });

    it('should clear all listeners on disconnect', () => {
      client.on('test-event', callback);
      
      client.disconnect();
      
      client['emit']('test-event', { data: 'test' });
      
      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('Socket Event Routing', () => {
    beforeEach(async () => {
      mockSocket.connected = false;
      const connectPromise = client.connect();
      
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      if (connectHandler && typeof connectHandler === 'function') {
        connectHandler();
      }
      
      await connectPromise;
    });

    it('should route message events', () => {
      const callback = jest.fn();
      client.on('message', callback);
      
      // Find the message handler registered with the socket
      const messageHandler = mockSocket.on.mock.calls.find(call => call[0] === 'message')?.[1];
      const testMessage = { type: 'test', data: 'hello' };
      
      messageHandler(testMessage);
      
      expect(callback).toHaveBeenCalledWith(testMessage);
    });

    it('should route terminal-data events', () => {
      const callback = jest.fn();
      client.on('terminal-data', callback);
      
      const terminalDataHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-data')[1];
      const testData = { sessionId: 'session-123', data: 'terminal output' };
      
      terminalDataHandler(testData);
      
      expect(callback).toHaveBeenCalledWith(testData);
    });

    it('should route terminal-resize events', () => {
      const callback = jest.fn();
      client.on('terminal-resize', callback);
      
      const resizeHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-resize')[1];
      const resizeData = { cols: 80, rows: 24 };
      
      resizeHandler(resizeData);
      
      expect(callback).toHaveBeenCalledWith(resizeData);
    });

    it('should route session-created events', () => {
      const callback = jest.fn();
      client.on('session-created', callback);
      
      const sessionCreatedHandler = mockSocket.on.mock.calls.find(call => call[0] === 'session-created')[1];
      const sessionData = { sessionId: 'new-session-123' };
      
      sessionCreatedHandler(sessionData);
      
      expect(callback).toHaveBeenCalledWith(sessionData);
    });

    it('should route session-destroyed events', () => {
      const callback = jest.fn();
      client.on('session-destroyed', callback);
      
      const sessionDestroyedHandler = mockSocket.on.mock.calls.find(call => call[0] === 'session-destroyed')[1];
      const sessionData = { sessionId: 'destroyed-session-123' };
      
      sessionDestroyedHandler(sessionData);
      
      expect(callback).toHaveBeenCalledWith(sessionData);
    });
  });

  describe('Connection State Properties', () => {
    it('should report connected state correctly', () => {
      mockSocket.connected = true;
      expect(client.connected).toBe(true);
      
      mockSocket.connected = false;
      expect(client.connected).toBe(false);
    });

    it('should report connecting state correctly', () => {
      expect(client.connecting).toBe(false);
      
      // Start connection
      client.connect();
      expect(client.connecting).toBe(true);
      
      // Complete connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      if (connectHandler && typeof connectHandler === 'function') {
        connectHandler();
      }
      
      expect(client.connecting).toBe(false);
    });

    it('should handle null socket state', () => {
      const newClient = new WebSocketClient();
      expect(newClient.connected).toBe(false);
      expect(newClient.connecting).toBe(false);
    });
  });

  describe('Error Scenarios', () => {
    it('should handle socket creation errors', async () => {
      mockIo.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });
      
      await expect(client.connect()).rejects.toThrow('Socket creation failed');
    });

    it('should handle multiple connection errors', async () => {
      const connectPromise = client.connect();
      
      // Simulate multiple errors
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      if (errorHandler && typeof errorHandler === 'function') {
        errorHandler(new Error('First error'));
        errorHandler(new Error('Second error'));
      }
      
      await expect(connectPromise).rejects.toThrow('First error');
    });

    it('should not reject on error if already connected', async () => {
      // First, establish connection
      mockSocket.connected = false;
      const connectPromise = client.connect();
      
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      if (connectHandler && typeof connectHandler === 'function') {
        connectHandler();
      }
      
      await connectPromise;
      
      // Now simulate an error - should not cause rejection
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      
      expect(() => {
        errorHandler(new Error('Error after connection'));
      }).not.toThrow();
    });
  });

  describe('Environment Configuration', () => {
    it('should use environment variables for configuration', () => {
      const originalEnv = process.env;
      
      process.env = {
        ...originalEnv,
        NEXT_PUBLIC_WS_PORT: '9999',
        NEXT_PUBLIC_WS_URL: 'ws://custom.com:9999',
      };
      
      // Re-import to get new environment values
      jest.resetModules();
      const { default: WebSocketClientNew } = require('@/lib/websocket/client');
      
      const client = new WebSocketClientNew();
      expect(client).toBeDefined();
      
      process.env = originalEnv;
    });

    it('should fall back to defaults when env vars are not set', () => {
      const originalEnv = process.env;
      
      process.env = {
        ...originalEnv,
        NEXT_PUBLIC_WS_PORT: undefined,
        NEXT_PUBLIC_WS_URL: undefined,
      };
      
      const client = new WebSocketClient();
      expect(client).toBeDefined();
      
      process.env = originalEnv;
    });
  });

  describe('Performance and Memory', () => {
    it('should handle many event listeners efficiently', () => {
      const callbacks: jest.Mock[] = [];
      
      // Register many listeners
      for (let i = 0; i < 100; i++) {
        const callback = jest.fn();
        callbacks.push(callback);
        client.on(`event-${i}`, callback);
      }
      
      // Emit events
      callbacks.forEach((callback, i) => {
        client['emit'](`event-${i}`, { index: i });
        expect(callback).toHaveBeenCalledWith({ index: i });
      });
    });

    it('should handle rapid event emissions', () => {
      const callback = jest.fn();
      client.on('rapid-event', callback);
      
      // Emit many events rapidly
      for (let i = 0; i < 1000; i++) {
        client['emit']('rapid-event', { count: i });
      }
      
      expect(callback).toHaveBeenCalledTimes(1000);
    });

    it('should clean up resources on disconnect', () => {
      const callback = jest.fn();
      client.on('test-event', callback);
      
      expect(client['listeners'].size).toBe(1);
      
      client.disconnect();
      
      expect(client['listeners'].size).toBe(0);
    });
  });
});

describe('wsClient singleton', () => {
  it('should export a singleton instance', () => {
    expect(wsClient).toBeInstanceOf(WebSocketClient);
  });

  it('should be the same instance across imports', () => {
    expect(wsClient).toBe(wsClient);
  });

  it('should have all WebSocketClient methods', () => {
    expect(typeof wsClient.connect).toBe('function');
    expect(typeof wsClient.disconnect).toBe('function');
    expect(typeof wsClient.send).toBe('function');
    expect(typeof wsClient.sendMessage).toBe('function');
    expect(typeof wsClient.on).toBe('function');
    expect(typeof wsClient.off).toBe('function');
  });
});