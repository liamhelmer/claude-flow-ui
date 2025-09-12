import { io, Socket } from 'socket.io-client';
import WebSocketClient, { wsClient } from '../client';

// Mock socket.io-client
jest.mock('socket.io-client');
const mockIo = io as jest.MockedFunction<typeof io>;

// Mock console methods to reduce noise in tests
const consoleMethods = ['log', 'warn', 'error'] as const;
const originalConsole = {} as Record<typeof consoleMethods[number], any>;

beforeAll(() => {
  consoleMethods.forEach(method => {
    originalConsole[method] = console[method];
    console[method] = jest.fn();
  });
});

afterAll(() => {
  consoleMethods.forEach(method => {
    console[method] = originalConsole[method];
  });
});

describe('WebSocketClient', () => {
  let mockSocket: jest.Mocked<Socket>;
  let client: WebSocketClient;

  beforeEach(() => {
    // Create a mock socket with all required methods
    mockSocket = {
      id: 'test-socket-id',
      connected: false,
      connect: jest.fn(),
      disconnect: jest.fn(),
      emit: jest.fn(),
      on: jest.fn(),
      off: jest.fn(),
      once: jest.fn(),
      removeAllListeners: jest.fn(),
      listeners: jest.fn().mockReturnValue([]),
    } as any;

    mockIo.mockReturnValue(mockSocket);
    client = new WebSocketClient('ws://test.com:3000');
  });

  afterEach(() => {
    jest.clearAllMocks();
    client.disconnect();
  });

  describe('constructor', () => {
    it('should initialize with default URL when none provided', () => {
      // Test default URL construction
      const defaultClient = new WebSocketClient();
      expect(defaultClient).toBeInstanceOf(WebSocketClient);
    });

    it('should initialize with provided URL', () => {
      const customClient = new WebSocketClient('ws://custom.com');
      expect(customClient).toBeInstanceOf(WebSocketClient);
    });

    it('should handle environment variable configuration', () => {
      const originalEnv = process.env;
      process.env.NEXT_PUBLIC_WS_PORT = '9999';
      process.env.NEXT_PUBLIC_WS_URL = 'ws://env-test.com:9999';

      // Re-import to get new environment variables
      jest.resetModules();
      const { default: EnvClient } = require('../client');
      const envClient = new EnvClient();
      
      expect(envClient).toBeInstanceOf(WebSocketClient);
      
      // Restore environment
      process.env = originalEnv;
    });
  });

  describe('connect method', () => {
    it('should establish connection successfully', async () => {
      const connectPromise = client.connect();
      
      expect(mockIo).toHaveBeenCalledWith('ws://test.com:3000', {
        transports: ['websocket', 'polling'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });

      // Simulate successful connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      expect(connectHandler).toBeDefined();
      
      mockSocket.connected = true;
      connectHandler?.();

      await expect(connectPromise).resolves.toBeUndefined();
      expect(client.connected).toBe(true);
    });

    it('should handle connection when already connected', async () => {
      mockSocket.connected = true;
      
      await expect(client.connect()).resolves.toBeUndefined();
      expect(mockIo).not.toHaveBeenCalled();
    });

    it('should handle concurrent connection attempts', async () => {
      const promise1 = client.connect();
      const promise2 = client.connect();
      
      // Simulate connection success
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      connectHandler?.();

      await Promise.all([promise1, promise2]);
      expect(mockIo).toHaveBeenCalledTimes(1);
    });

    it('should reject on connection error', async () => {
      const connectPromise = client.connect();
      
      // Simulate connection error
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      expect(errorHandler).toBeDefined();
      
      const testError = new Error('Connection failed');
      errorHandler?.(testError);

      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('should not reject on connection error if already connected', async () => {
      const connectPromise = client.connect();
      
      // First simulate successful connection
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      connectHandler?.();

      // Then simulate an error (which shouldn't reject the promise)
      const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
      const testError = new Error('Secondary error');
      errorHandler?.(testError);

      await expect(connectPromise).resolves.toBeUndefined();
    });

    it('should set up all required event listeners', async () => {
      client.connect();

      const expectedEvents = [
        'connect', 'disconnect', 'connect_error', 'message',
        'terminal-data', 'terminal-resize', 'terminal-config',
        'terminal-error', 'connection-change', 'session-created',
        'session-destroyed'
      ];

      expectedEvents.forEach(event => {
        expect(mockSocket.on).toHaveBeenCalledWith(event, expect.any(Function));
      });
    });
  });

  describe('disconnect method', () => {
    it('should disconnect and clean up resources', () => {
      client.disconnect();
      
      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });

    it('should handle disconnect when not connected', () => {
      const newClient = new WebSocketClient();
      newClient.disconnect();
      
      expect(newClient.connected).toBe(false);
    });
  });

  describe('send method', () => {
    it('should send message when connected', () => {
      mockSocket.connected = true;
      
      client.send('test-event', { data: 'test' });
      
      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', { data: 'test' });
    });

    it('should not send message when disconnected', () => {
      mockSocket.connected = false;
      
      client.send('test-event', { data: 'test' });
      
      expect(mockSocket.emit).not.toHaveBeenCalled();
      expect(console.warn).toHaveBeenCalledWith('WebSocket not connected, cannot send message');
    });

    it('should handle various data types', () => {
      mockSocket.connected = true;

      const testCases = [
        { data: 'string' },
        { data: 123 },
        { data: true },
        { data: null },
        { data: { nested: { object: 'value' } } },
        { data: [1, 2, 3] },
      ];

      testCases.forEach((testData, index) => {
        client.send(`event-${index}`, testData);
        expect(mockSocket.emit).toHaveBeenCalledWith(`event-${index}`, testData);
      });
    });
  });

  describe('sendMessage method', () => {
    it('should send message via send method', () => {
      mockSocket.connected = true;
      const testMessage = { type: 'test', payload: { id: 1 } };
      
      client.sendMessage(testMessage);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('message', testMessage);
    });
  });

  describe('event listener management', () => {
    let testCallback: jest.Mock;

    beforeEach(() => {
      testCallback = jest.fn();
    });

    it('should add event listeners', () => {
      client.on('test-event', testCallback);
      
      // Trigger the event to test it was registered
      const handler = client['emit'] as any;
      handler.call(client, 'test-event', { data: 'test' });
      
      expect(testCallback).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should remove specific event listeners', () => {
      client.on('test-event', testCallback);
      client.off('test-event', testCallback);
      
      const handler = client['emit'] as any;
      handler.call(client, 'test-event', { data: 'test' });
      
      expect(testCallback).not.toHaveBeenCalled();
    });

    it('should handle removing non-existent listeners', () => {
      expect(() => {
        client.off('non-existent', testCallback);
      }).not.toThrow();
    });

    it('should support multiple listeners for same event', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      
      client.on('multi-event', callback1);
      client.on('multi-event', callback2);
      
      const handler = client['emit'] as any;
      handler.call(client, 'multi-event', { data: 'test' });
      
      expect(callback1).toHaveBeenCalledWith({ data: 'test' });
      expect(callback2).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should clear all listeners on disconnect', () => {
      client.on('test-event', testCallback);
      client.disconnect();
      
      const handler = client['emit'] as any;
      handler.call(client, 'test-event', { data: 'test' });
      
      expect(testCallback).not.toHaveBeenCalled();
    });
  });

  describe('socket event routing', () => {
    beforeEach(async () => {
      // Set up connection
      const connectPromise = client.connect();
      const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      connectHandler?.();
      await connectPromise;
    });

    it('should route socket events to client listeners', () => {
      const testCallback = jest.fn();
      client.on('terminal-data', testCallback);
      
      // Find and trigger the socket handler
      const socketHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      const testData = { sessionId: 'test', data: 'terminal output' };
      socketHandler?.(testData);
      
      expect(testCallback).toHaveBeenCalledWith(testData);
    });

    it('should handle disconnect events', () => {
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      
      disconnectHandler?.('server disconnect');
      
      expect(console.log).toHaveBeenCalledWith('[WebSocket] Disconnected:', 'server disconnect');
    });
  });

  describe('connection state properties', () => {
    it('should return correct connected state', () => {
      expect(client.connected).toBe(false);
      
      mockSocket.connected = true;
      expect(client.connected).toBe(true);
    });

    it('should return correct connecting state', () => {
      expect(client.connecting).toBe(false);
      
      // Start connection attempt
      client.connect();
      expect(client.connecting).toBe(true);
    });
  });

  describe('error scenarios and edge cases', () => {
    it('should handle socket creation failure', () => {
      mockIo.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });
      
      expect(() => client.connect()).toThrow('Socket creation failed');
    });

    it('should handle malformed event data', () => {
      const testCallback = jest.fn();
      client.on('test-event', testCallback);
      
      // Send undefined data
      const handler = client['emit'] as any;
      handler.call(client, 'test-event', undefined);
      
      expect(testCallback).toHaveBeenCalledWith(undefined);
      expect(() => handler.call(client, 'test-event', undefined)).not.toThrow();
    });

    it('should handle reconnection scenarios', async () => {
      // Initial connection
      let connectPromise = client.connect();
      let connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
      mockSocket.connected = true;
      connectHandler?.();
      await connectPromise;

      // Simulate disconnect
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      mockSocket.connected = false;
      disconnectHandler?.('transport close');

      // Simulate reconnection
      mockSocket.connected = true;
      connectHandler?.();
      
      expect(client.connected).toBe(true);
    });
  });

  describe('singleton wsClient instance', () => {
    it('should export a singleton wsClient instance', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should maintain state across imports', () => {
      const { wsClient: importedClient } = require('../client');
      expect(importedClient).toBe(wsClient);
    });
  });

  describe('environment handling', () => {
    it('should handle browser vs server environment', () => {
      // Test that window check doesn't break in Node environment
      expect(() => {
        new WebSocketClient();
      }).not.toThrow();
    });
  });
});