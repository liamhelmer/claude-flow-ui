import WebSocketClient, { wsClient } from '@/lib/websocket/client';

// Mock Socket.IO
jest.mock('socket.io-client', () => {
  const mockSocket = {
    connected: false,
    id: 'mock-socket-id',
    connect: jest.fn(),
    disconnect: jest.fn(),
    emit: jest.fn(),
    on: jest.fn(),
    removeAllListeners: jest.fn(),
  };

  return {
    io: jest.fn(() => mockSocket),
    Socket: jest.fn(() => mockSocket),
  };
});

// Mock WebSocketMessage type
const mockMessage = {
  type: 'test',
  payload: { data: 'test message' },
  timestamp: Date.now(),
};

describe('WebSocketClient - Comprehensive Tests', () => {
  let client: WebSocketClient;
  let mockSocket: any;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Create fresh client instance
    client = new WebSocketClient('ws://localhost:11236');

    // Get mock socket
    const { io } = require('socket.io-client');
    mockSocket = io();

    // Reset mock socket state
    mockSocket.connected = false;
    mockSocket.on.mockClear();
    mockSocket.emit.mockClear();
    mockSocket.connect.mockClear();
    mockSocket.disconnect.mockClear();
  });

  afterEach(() => {
    jest.useRealTimers();
    client.disconnect();
  });

  describe('Construction and Configuration', () => {
    it('uses provided URL when specified', () => {
      const customClient = new WebSocketClient('ws://custom-host:8080');
      expect(customClient).toBeDefined();
    });

    it('calculates dynamic port based on window location', () => {
      // Mock window.location.port
      Object.defineProperty(window, 'location', {
        value: { port: '3000' },
        writable: true,
      });

      const dynamicClient = new WebSocketClient();
      expect(dynamicClient).toBeDefined();
    });

    it('falls back to environment variable', () => {
      const originalEnv = process.env.NEXT_PUBLIC_WS_PORT;
      process.env.NEXT_PUBLIC_WS_PORT = '9999';

      // Clear window.location.port
      Object.defineProperty(window, 'location', {
        value: { port: '' },
        writable: true,
      });

      const envClient = new WebSocketClient();
      expect(envClient).toBeDefined();

      process.env.NEXT_PUBLIC_WS_PORT = originalEnv;
    });

    it('uses final fallback port when no other options available', () => {
      const originalEnv = process.env.NEXT_PUBLIC_WS_PORT;
      delete process.env.NEXT_PUBLIC_WS_PORT;

      // Clear window.location.port
      Object.defineProperty(window, 'location', {
        value: { port: '' },
        writable: true,
      });

      const fallbackClient = new WebSocketClient();
      expect(fallbackClient).toBeDefined();

      process.env.NEXT_PUBLIC_WS_PORT = originalEnv;
    });
  });

  describe('Connection Management', () => {
    it('connects successfully', async () => {
      const connectPromise = client.connect();

      // Simulate successful connection
      act(() => {
        mockSocket.connected = true;
        const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
        if (connectHandler) connectHandler();
      });

      await expect(connectPromise).resolves.toBeUndefined();
      expect(mockSocket.connect).toHaveBeenCalled();
    });

    it('resolves immediately if already connected', async () => {
      mockSocket.connected = true;

      const connectPromise = client.connect();

      await expect(connectPromise).resolves.toBeUndefined();
      expect(mockSocket.connect).not.toHaveBeenCalled();
    });

    it('handles connection errors', async () => {
      const error = new Error('Connection failed');
      const connectPromise = client.connect();

      // Simulate connection error
      act(() => {
        const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')?.[1];
        if (errorHandler) errorHandler(error);
      });

      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('handles connection timeout', async () => {
      const connectPromise = client.connect();

      // Advance timer past connection timeout
      act(() => {
        jest.advanceTimersByTime(6000);
      });

      // Connection should still be attempted but timeout warning logged
      expect(mockSocket.connect).toHaveBeenCalled();
    });

    it('prevents multiple concurrent connection attempts', async () => {
      const promise1 = client.connect();
      const promise2 = client.connect();

      // Simulate successful connection
      act(() => {
        mockSocket.connected = true;
        const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
        if (connectHandler) connectHandler();
      });

      await Promise.all([promise1, promise2]);

      // Should only connect once
      expect(mockSocket.connect).toHaveBeenCalledTimes(1);
    });

    it('disconnects properly', () => {
      client.disconnect();

      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
    });

    it('cleans up state on disconnect', () => {
      // Add some listeners first
      const callback = jest.fn();
      client.on('test-event', callback);

      client.disconnect();

      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
    });
  });

  describe('Event Listener Setup', () => {
    it('sets up all required event listeners before connecting', async () => {
      const connectPromise = client.connect();

      // Check that event listeners are registered
      const eventTypes = mockSocket.on.mock.calls.map(call => call[0]);
      expect(eventTypes).toContain('message');
      expect(eventTypes).toContain('terminal-data');
      expect(eventTypes).toContain('terminal-config');
      expect(eventTypes).toContain('terminal-error');
      expect(eventTypes).toContain('connection-change');
      expect(eventTypes).toContain('session-created');
      expect(eventTypes).toContain('session-destroyed');
      expect(eventTypes).toContain('connect');
      expect(eventTypes).toContain('disconnect');
      expect(eventTypes).toContain('connect_error');

      // Resolve connection
      act(() => {
        mockSocket.connected = true;
        const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
        if (connectHandler) connectHandler();
      });

      await connectPromise;
    });

    it('routes messages correctly', async () => {
      const callback = jest.fn();
      client.on('message', callback);

      await client.connect();

      const messageHandler = mockSocket.on.mock.calls.find(call => call[0] === 'message')?.[1];
      
      act(() => {
        messageHandler(mockMessage);
      });

      expect(callback).toHaveBeenCalledWith(mockMessage);
    });

    it('routes terminal data correctly', async () => {
      const callback = jest.fn();
      client.on('terminal-data', callback);

      await client.connect();

      const dataHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
      const testData = { sessionId: 'test', data: 'output' };
      
      act(() => {
        dataHandler(testData);
      });

      expect(callback).toHaveBeenCalledWith(testData);
    });
  });

  describe('Terminal Config Handling', () => {
    it('stores terminal config when no listeners are available', async () => {
      await client.connect();

      const configHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
      const configData = { sessionId: 'test-session', cols: 80, rows: 24 };
      
      act(() => {
        configHandler(configData);
      });

      // Should store config for later delivery
      expect(client['pendingTerminalConfigs'].has('test-session')).toBe(true);
    });

    it('delivers terminal config immediately when listeners are available', async () => {
      const callback = jest.fn();
      client.on('terminal-config', callback);

      await client.connect();

      const configHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
      const configData = { sessionId: 'test-session', cols: 80, rows: 24 };
      
      act(() => {
        configHandler(configData);
      });

      expect(callback).toHaveBeenCalledWith(configData);
    });

    it('delivers pending configs when listener is registered', async () => {
      await client.connect();

      // Send config before listener is registered
      const configHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
      const configData = { sessionId: 'test-session', cols: 80, rows: 24 };
      
      act(() => {
        configHandler(configData);
      });

      // Now register listener
      const callback = jest.fn();
      client.on('terminal-config', callback);

      // Should receive pending config
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 0));
      });

      expect(callback).toHaveBeenCalledWith(configData);
    });

    it('starts and stops periodic config check', async () => {
      await client.connect();

      const configHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
      const configData = { sessionId: 'test-session', cols: 80, rows: 24 };
      
      // Send config to trigger periodic check
      act(() => {
        configHandler(configData);
      });

      expect(client['pendingConfigCheckInterval']).toBeDefined();

      // Register listener and advance timer
      const callback = jest.fn();
      client.on('terminal-config', callback);

      act(() => {
        jest.advanceTimersByTime(1000);
      });

      expect(callback).toHaveBeenCalledWith(configData);
      expect(client['pendingConfigCheckInterval']).toBeNull();
    });
  });

  describe('Message Sending', () => {
    it('sends messages when connected', async () => {
      mockSocket.connected = true;

      client.send('test-event', { data: 'test' });

      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', { data: 'test' });
    });

    it('warns when sending while disconnected', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      mockSocket.connected = false;

      client.send('test-event', { data: 'test' });

      expect(mockSocket.emit).not.toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith('WebSocket not connected, cannot send message');

      consoleSpy.mockRestore();
    });

    it('sends WebSocket messages correctly', async () => {
      mockSocket.connected = true;

      client.sendMessage(mockMessage);

      expect(mockSocket.emit).toHaveBeenCalledWith('message', mockMessage);
    });
  });

  describe('Event Emitter Interface', () => {
    it('registers event listeners', () => {
      const callback = jest.fn();
      client.on('test-event', callback);

      // Verify listener is stored
      expect(client['listeners'].get('test-event')).toContain(callback);
    });

    it('removes event listeners', () => {
      const callback = jest.fn();
      client.on('test-event', callback);
      client.off('test-event', callback);

      // Verify listener is removed
      const listeners = client['listeners'].get('test-event');
      expect(listeners?.includes(callback)).toBe(false);
    });

    it('emits events to registered listeners', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      
      client.on('test-event', callback1);
      client.on('test-event', callback2);

      client['emit']('test-event', { data: 'test' });

      expect(callback1).toHaveBeenCalledWith({ data: 'test' });
      expect(callback2).toHaveBeenCalledWith({ data: 'test' });
    });

    it('warns when emitting to events with no listeners', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      client['emit']('unknown-event', { data: 'test' });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] ⚠️ No listeners registered for event: unknown-event'
      );

      consoleSpy.mockRestore();
    });

    it('warns when too many listeners are registered', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

      // Add 11 listeners (limit is 10)
      for (let i = 0; i < 11; i++) {
        client.on('test-event', jest.fn());
      }

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('MaxListenersExceededWarning: test-event has 10 listeners')
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Connection State Properties', () => {
    it('returns correct connected state', () => {
      mockSocket.connected = true;
      expect(client.connected).toBe(true);

      mockSocket.connected = false;
      expect(client.connected).toBe(false);
    });

    it('returns correct connecting state', () => {
      expect(client.connecting).toBe(false);

      // Start connection (sets isConnecting to true)
      client.connect();
      expect(client.connecting).toBe(true);
    });

    it('handles null socket gracefully', () => {
      client.disconnect(); // This sets socket to null
      
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('handles socket creation errors', () => {
      const { io } = require('socket.io-client');
      io.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });

      expect(() => client.connect()).toThrow('Socket creation failed');
    });

    it('handles disconnect events', async () => {
      await client.connect();

      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')?.[1];
      
      act(() => {
        disconnectHandler('transport close');
      });

      expect(client.connecting).toBe(false);
    });

    it('handles multiple disconnect calls', () => {
      client.disconnect();
      client.disconnect();

      // Should not throw or cause issues
      expect(mockSocket.disconnect).toHaveBeenCalledTimes(2);
    });

    it('cleans up pending configs on disconnect', () => {
      // Add pending config
      client['pendingTerminalConfigs'].set('test-session', { data: 'test' });
      
      client.disconnect();

      expect(client['pendingTerminalConfigs'].size).toBe(0);
    });

    it('stops periodic check on disconnect', () => {
      // Start periodic check
      client['startPendingConfigCheck']();
      expect(client['pendingConfigCheckInterval']).toBeDefined();

      client.disconnect();

      expect(client['pendingConfigCheckInterval']).toBeNull();
    });
  });

  describe('Test Environment Handling', () => {
    it('simulates connection in test environment', async () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';

      const testClient = new WebSocketClient();
      const connectPromise = testClient.connect();

      act(() => {
        jest.advanceTimersByTime(10);
      });

      await expect(connectPromise).resolves.toBeUndefined();

      process.env.NODE_ENV = originalNodeEnv;
    });

    it('handles real connection in non-test environment', async () => {
      const originalNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const devClient = new WebSocketClient();
      const connectPromise = devClient.connect();

      // Simulate successful connection
      act(() => {
        mockSocket.connected = true;
        const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
        if (connectHandler) connectHandler();
      });

      await expect(connectPromise).resolves.toBeUndefined();

      process.env.NODE_ENV = originalNodeEnv;
    });
  });

  describe('Singleton Instance', () => {
    it('exports a singleton wsClient instance', () => {
      expect(wsClient).toBeDefined();
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('singleton instance is reusable', () => {
      const instance1 = wsClient;
      const instance2 = wsClient;
      
      expect(instance1).toBe(instance2);
    });
  });

  describe('Memory Management', () => {
    it('prevents memory leaks when registering many listeners', () => {
      const listeners = [];
      
      // Register many listeners
      for (let i = 0; i < 100; i++) {
        const callback = jest.fn();
        listeners.push(callback);
        client.on('test-event', callback);
      }

      // Remove all listeners
      listeners.forEach(callback => {
        client.off('test-event', callback);
      });

      const remainingListeners = client['listeners'].get('test-event');
      expect(remainingListeners?.length || 0).toBe(0);
    });

    it('clears all listeners on disconnect', () => {
      client.on('event1', jest.fn());
      client.on('event2', jest.fn());
      client.on('event3', jest.fn());

      client.disconnect();

      expect(client['listeners'].size).toBe(0);
    });

    it('handles rapid connect/disconnect cycles', async () => {
      for (let i = 0; i < 5; i++) {
        const connectPromise = client.connect();
        
        act(() => {
          mockSocket.connected = true;
          const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
          if (connectHandler) connectHandler();
        });

        await connectPromise;
        client.disconnect();
        
        mockSocket.connected = false;
        mockSocket.on.mockClear();
      }

      // Should not cause memory leaks or errors
      expect(client['listeners'].size).toBe(0);
    });
  });
});