import WebSocketClient, { wsClient } from '@/lib/websocket/client';

// Mock socket.io-client
jest.mock('socket.io-client');

const mockSocket = {
  connected: false,
  id: 'mock-socket-id',
  connect: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
};

const mockIo = jest.fn(() => mockSocket);

describe('WebSocketClient', () => {
  let client: WebSocketClient;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock io function
    const socketIo = require('socket.io-client');
    socketIo.io = mockIo;
    
    // Reset mock socket state
    mockSocket.connected = false;
    mockSocket.connect.mockClear();
    mockSocket.disconnect.mockClear();
    mockSocket.emit.mockClear();
    mockSocket.on.mockClear();
    mockSocket.off.mockClear();

    client = new WebSocketClient('ws://test:1234');
  });

  describe('initialization', () => {
    it('should create client with default URL', () => {
      const defaultClient = new WebSocketClient();
      expect(defaultClient).toBeInstanceOf(WebSocketClient);
    });

    it('should create client with custom URL', () => {
      const customClient = new WebSocketClient('ws://custom:5678');
      expect(customClient).toBeInstanceOf(WebSocketClient);
    });

    it('should have initial state', () => {
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });
  });

  describe('connection management', () => {
    it('should connect successfully', async () => {
      // Setup mock to resolve connection
      mockIo.mockReturnValue(mockSocket);
      
      // Simulate successful connection
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 0);
        }
      });

      const connectPromise = client.connect();
      await connectPromise;

      expect(mockIo).toHaveBeenCalledWith('ws://test:1234', {
        transports: ['websocket', 'polling'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });
    });

    it('should handle connection errors', async () => {
      const error = new Error('Connection failed');
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect_error') {
          setTimeout(() => callback(error), 0);
        }
      });

      await expect(client.connect()).rejects.toThrow('Connection failed');
    });

    it('should not connect if already connected', async () => {
      mockSocket.connected = true;

      await client.connect();

      expect(mockIo).not.toHaveBeenCalled();
    });

    it('should handle concurrent connection attempts', async () => {
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 100);
        }
      });

      const promise1 = client.connect();
      const promise2 = client.connect();

      await Promise.all([promise1, promise2]);

      expect(mockIo).toHaveBeenCalledTimes(1);
    });

    it('should disconnect properly', () => {
      mockSocket.connected = true;
      client['socket'] = mockSocket as any;

      client.disconnect();

      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });

    it('should handle disconnect when not connected', () => {
      client.disconnect();
      expect(mockSocket.disconnect).not.toHaveBeenCalled();
    });
  });

  describe('message sending', () => {
    beforeEach(() => {
      mockSocket.connected = true;
      client['socket'] = mockSocket as any;
    });

    it('should send event with data', () => {
      client.send('test-event', { data: 'test' });

      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', { data: 'test' });
    });

    it('should send message via sendMessage method', () => {
      const message = { type: 'test', payload: { data: 'test' } };
      client.sendMessage(message);

      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should warn when sending while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockSocket.connected = false;

      client.send('test-event', { data: 'test' });

      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message');
      expect(mockSocket.emit).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    it('should handle null socket gracefully', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      client['socket'] = null;

      client.send('test-event', { data: 'test' });

      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message');

      consoleSpy.mockRestore();
    });
  });

  describe('event handling', () => {
    it('should register event listeners', () => {
      const callback = jest.fn();
      
      client.on('test-event', callback);

      const listeners = client['listeners'].get('test-event');
      expect(listeners).toContain(callback);
    });

    it('should register multiple listeners for same event', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      
      client.on('test-event', callback1);
      client.on('test-event', callback2);

      const listeners = client['listeners'].get('test-event');
      expect(listeners).toHaveLength(2);
      expect(listeners).toContain(callback1);
      expect(listeners).toContain(callback2);
    });

    it('should remove event listeners', () => {
      const callback = jest.fn();
      
      client.on('test-event', callback);
      client.off('test-event', callback);

      const listeners = client['listeners'].get('test-event');
      expect(listeners).not.toContain(callback);
    });

    it('should handle removing non-existent listener', () => {
      const callback = jest.fn();
      
      expect(() => {
        client.off('non-existent', callback);
      }).not.toThrow();
    });

    it('should emit events to registered listeners', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      
      client.on('test-event', callback1);
      client.on('test-event', callback2);

      client['emit']('test-event', { data: 'test' });

      expect(callback1).toHaveBeenCalledWith({ data: 'test' });
      expect(callback2).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should not emit to removed listeners', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      
      client.on('test-event', callback1);
      client.on('test-event', callback2);
      client.off('test-event', callback1);

      client['emit']('test-event', { data: 'test' });

      expect(callback1).not.toHaveBeenCalled();
      expect(callback2).toHaveBeenCalledWith({ data: 'test' });
    });
  });

  describe('socket event routing', () => {
    beforeEach(() => {
      mockSocket.connected = true;
      client['socket'] = mockSocket as any;
    });

    it('should set up socket event handlers during connection', async () => {
      const eventHandlers = new Map();
      
      mockSocket.on.mockImplementation((event, callback) => {
        eventHandlers.set(event, callback);
        if (event === 'connect') {
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 0);
        }
      });

      await client.connect();

      expect(mockSocket.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('connect_error', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('message', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('terminal-resize', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('session-created', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('session-destroyed', expect.any(Function));
    });

    it('should route socket events to emit', async () => {
      const eventHandlers = new Map();
      const clientEmitSpy = jest.spyOn(client as any, 'emit');
      
      mockSocket.on.mockImplementation((event, callback) => {
        eventHandlers.set(event, callback);
        if (event === 'connect') {
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 0);
        }
      });

      await client.connect();

      // Test message routing
      const messageHandler = eventHandlers.get('message');
      const testMessage = { type: 'test', data: 'test' };
      messageHandler(testMessage);
      expect(clientEmitSpy).toHaveBeenCalledWith('message', testMessage);

      // Test terminal-data routing
      const terminalDataHandler = eventHandlers.get('terminal-data');
      const terminalData = { sessionId: 'test', data: 'output' };
      terminalDataHandler(terminalData);
      expect(clientEmitSpy).toHaveBeenCalledWith('terminal-data', terminalData);

      clientEmitSpy.mockRestore();
    });

    it('should handle disconnect event', async () => {
      const eventHandlers = new Map();
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
      
      mockSocket.on.mockImplementation((event, callback) => {
        eventHandlers.set(event, callback);
        if (event === 'connect') {
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 0);
        }
      });

      await client.connect();

      const disconnectHandler = eventHandlers.get('disconnect');
      disconnectHandler('transport close');

      expect(consoleSpy).toHaveBeenCalledWith('[WebSocket] Disconnected:', 'transport close');
      expect(client.connecting).toBe(false);

      consoleSpy.mockRestore();
    });
  });

  describe('state properties', () => {
    it('should return correct connected state', () => {
      mockSocket.connected = false;
      client['socket'] = mockSocket as any;
      expect(client.connected).toBe(false);

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

      client['isConnecting'] = false;
      expect(client.connecting).toBe(false);
    });
  });

  describe('cleanup', () => {
    it('should clear listeners on disconnect', () => {
      const callback = jest.fn();
      client.on('test-event', callback);
      
      expect(client['listeners'].get('test-event')).toContain(callback);

      client.disconnect();

      expect(client['listeners'].size).toBe(0);
    });

    it('should reset connecting state on disconnect', () => {
      client['isConnecting'] = true;
      
      client.disconnect();

      expect(client.connecting).toBe(false);
    });
  });

  describe('singleton instance', () => {
    it('should export a singleton wsClient instance', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should be the same instance across imports', () => {
      const { wsClient: wsClient2 } = require('@/lib/websocket/client');
      expect(wsClient).toBe(wsClient2);
    });
  });

  describe('environment configuration', () => {
    it('should use environment variables for configuration', () => {
      // Test is somewhat limited since we can't easily change process.env in Jest
      // But we can verify the module loads without error
      expect(wsClient).toBeDefined();
    });
  });

  describe('error scenarios', () => {
    it('should handle socket creation failure', () => {
      mockIo.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });

      expect(() => client.connect()).rejects.toThrow();
    });

    it('should handle malformed message data', () => {
      mockSocket.connected = true;
      client['socket'] = mockSocket as any;

      expect(() => {
        client.send('test', undefined);
        client.send('test', null);
        client.sendMessage(undefined as any);
      }).not.toThrow();
    });

    it('should handle event emission with no listeners', () => {
      expect(() => {
        client['emit']('non-existent-event', { data: 'test' });
      }).not.toThrow();
    });
  });
});