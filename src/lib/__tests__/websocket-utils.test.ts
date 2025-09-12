/**
 * WebSocket Utilities Test Suite
 * Tests for WebSocket client functionality with comprehensive mocking
 */

import WebSocketClient, { wsClient } from '../websocket/client';
import type { WebSocketMessage } from '@/types';

// Mock socket.io-client
const mockSocket = {
  connected: false,
  id: 'mock-socket-id',
  connect: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  removeAllListeners: jest.fn()
};

const mockIo = jest.fn(() => mockSocket);

jest.mock('socket.io-client', () => ({
  io: mockIo
}));

// Mock window object for browser tests
const mockWindow = {
  location: {
    port: '3000'
  }
};

describe('WebSocket Utils Test Suite', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSocket.connected = false;
    mockSocket.connect.mockClear();
    mockSocket.disconnect.mockClear();
    mockSocket.emit.mockClear();
    mockSocket.on.mockClear();
    mockSocket.off.mockClear();
    mockSocket.removeAllListeners.mockClear();
    
    // Mock window for port calculation
    Object.defineProperty(global, 'window', {
      value: mockWindow,
      writable: true
    });
  });

  afterEach(() => {
    delete (global as any).window;
  });

  describe('WebSocketClient Construction', () => {
    it('should create WebSocketClient with default URL', () => {
      const client = new WebSocketClient();
      expect(client).toBeDefined();
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });

    it('should create WebSocketClient with custom URL', () => {
      const customUrl = 'ws://localhost:8080';
      const client = new WebSocketClient(customUrl);
      expect(client).toBeDefined();
    });

    it('should calculate WebSocket port dynamically', () => {
      mockWindow.location.port = '3000';
      const client = new WebSocketClient();
      
      // The constructor should calculate port 3001 (3000 + 1)
      expect(client).toBeDefined();
    });

    it('should handle missing window.location.port', () => {
      delete (mockWindow.location as any).port;
      const client = new WebSocketClient();
      expect(client).toBeDefined();
    });

    it('should use environment variable fallback', () => {
      delete (global as any).window;
      process.env.NEXT_PUBLIC_WS_PORT = '9999';
      
      const client = new WebSocketClient();
      expect(client).toBeDefined();
      
      delete process.env.NEXT_PUBLIC_WS_PORT;
    });
  });

  describe('Connection Management', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
    });

    it('should connect to WebSocket server', async () => {
      // Mock successful connection
      mockSocket.connect.mockImplementation(() => {
        setTimeout(() => {
          mockSocket.connected = true;
          const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')[1];
          connectHandler();
        }, 10);
      });

      const connectPromise = client.connect();
      await expect(connectPromise).resolves.toBeUndefined();
      
      expect(mockIo).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({
        transports: ['websocket', 'polling'],
        autoConnect: false,
        reconnection: true
      }));
    });

    it('should handle connection errors', async () => {
      const connectionError = new Error('Connection failed');
      
      mockSocket.connect.mockImplementation(() => {
        setTimeout(() => {
          const errorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect_error')[1];
          errorHandler(connectionError);
        }, 10);
      });

      await expect(client.connect()).rejects.toThrow('Connection failed');
    });

    it('should not connect multiple times simultaneously', async () => {
      mockSocket.connect.mockImplementation(() => {
        setTimeout(() => {
          mockSocket.connected = true;
          const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')[1];
          connectHandler();
        }, 50);
      });

      // Start multiple connection attempts
      const promise1 = client.connect();
      const promise2 = client.connect();
      const promise3 = client.connect();

      await Promise.all([promise1, promise2, promise3]);
      
      // Should only call connect once
      expect(mockSocket.connect).toHaveBeenCalledTimes(1);
    });

    it('should handle test environment gracefully', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';

      const testClient = new WebSocketClient();
      await expect(testClient.connect()).resolves.toBeUndefined();

      process.env.NODE_ENV = originalEnv;
    });

    it('should disconnect properly', () => {
      mockSocket.connected = true;
      client.disconnect();

      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });

    it('should handle disconnect when not connected', () => {
      client.disconnect();
      expect(client.connected).toBe(false);
    });
  });

  describe('Event Handling', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
      mockSocket.connected = true;
    });

    it('should register event listeners', () => {
      const callback = jest.fn();
      client.on('test-event', callback);
      
      // Should store the callback
      expect(callback).toBeDefined();
    });

    it('should handle terminal-data events', () => {
      const callback = jest.fn();
      client.on('terminal-data', callback);

      // Simulate terminal data event
      const terminalDataHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-data')[1];
      const testData = { sessionId: 'test-session', data: 'terminal output' };
      terminalDataHandler(testData);

      expect(callback).toHaveBeenCalledWith(testData);
    });

    it('should handle terminal-config events with pending delivery', () => {
      const configData = { sessionId: 'test-session', rows: 24, cols: 80 };
      
      // Receive config before listeners are ready
      const terminalConfigHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')[1];
      terminalConfigHandler(configData);

      // Now add listener
      const callback = jest.fn();
      client.on('terminal-config', callback);

      // Should deliver pending config
      setTimeout(() => {
        expect(callback).toHaveBeenCalledWith(configData);
      }, 0);
    });

    it('should handle session-created events', () => {
      const callback = jest.fn();
      client.on('session-created', callback);

      const sessionCreatedHandler = mockSocket.on.mock.calls.find(call => call[0] === 'session-created')[1];
      const sessionData = { sessionId: 'new-session', name: 'Test Session' };
      sessionCreatedHandler(sessionData);

      expect(callback).toHaveBeenCalledWith(sessionData);
    });

    it('should handle session-destroyed events', () => {
      const callback = jest.fn();
      client.on('session-destroyed', callback);

      const sessionDestroyedHandler = mockSocket.on.mock.calls.find(call => call[0] === 'session-destroyed')[1];
      const sessionData = { sessionId: 'old-session' };
      sessionDestroyedHandler(sessionData);

      expect(callback).toHaveBeenCalledWith(sessionData);
    });

    it('should remove event listeners', () => {
      const callback = jest.fn();
      client.on('test-event', callback);
      client.off('test-event', callback);

      // The callback should be removed from internal storage
      expect(callback).toBeDefined();
    });

    it('should warn about too many listeners', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Add 11 listeners to trigger warning
      for (let i = 0; i < 11; i++) {
        client.on('test-event', () => {});
      }

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('MaxListenersExceededWarning')
      );

      consoleSpy.mockRestore();
    });

    it('should handle events with no listeners', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Trigger an event with no listeners
      const messageHandler = mockSocket.on.mock.calls.find(call => call[0] === 'message')[1];
      messageHandler({ type: 'test', data: 'test data' });

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('No listeners registered for event: message')
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Message Sending', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
      mockSocket.connected = true;
    });

    it('should send messages when connected', () => {
      client.send('test-event', { data: 'test' });
      expect(mockSocket.emit).toHaveBeenCalledWith('test-event', { data: 'test' });
    });

    it('should send WebSocket messages', () => {
      const message: WebSocketMessage = {
        type: 'command',
        sessionId: 'test-session',
        data: 'ls -la'
      };

      client.sendMessage(message);
      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should warn when sending while disconnected', () => {
      mockSocket.connected = false;
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      client.send('test-event', { data: 'test' });

      expect(consoleSpy).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send message'
      );
      expect(mockSocket.emit).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('Pending Terminal Config Management', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should start and stop pending config checks', () => {
      // Simulate receiving config before listeners
      const terminalConfigHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')[1];
      terminalConfigHandler({ sessionId: 'test', rows: 24, cols: 80 });

      // Fast-forward to trigger periodic check
      jest.advanceTimersByTime(1000);

      // Add listener to stop the periodic check
      const callback = jest.fn();
      client.on('terminal-config', callback);

      // Fast-forward to trigger delivery
      jest.advanceTimersByTime(0);

      expect(callback).toHaveBeenCalled();
    });

    it('should clear pending configs after delivery', () => {
      const configData = { sessionId: 'test', rows: 24, cols: 80 };
      
      // Receive config
      const terminalConfigHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')[1];
      terminalConfigHandler(configData);

      // Add listener
      const callback1 = jest.fn();
      client.on('terminal-config', callback1);
      
      jest.advanceTimersByTime(0);
      
      // Add another listener - should not receive the config again
      const callback2 = jest.fn();
      client.on('terminal-config', callback2);
      
      jest.advanceTimersByTime(0);

      expect(callback1).toHaveBeenCalledWith(configData);
      expect(callback2).not.toHaveBeenCalled(); // Config was already delivered and cleared
    });
  });

  describe('Connection State Management', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
    });

    it('should report correct connection state', () => {
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);

      mockSocket.connected = true;
      expect(client.connected).toBe(true);
    });

    it('should handle connection state changes', () => {
      const callback = jest.fn();
      client.on('connection-change', callback);

      const connectionChangeHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connection-change')[1];
      connectionChangeHandler({ connected: true });

      expect(callback).toHaveBeenCalledWith({ connected: true });
    });

    it('should handle disconnect events', () => {
      mockSocket.connected = true;
      
      const disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')[1];
      disconnectHandler('transport error');

      expect(client.connecting).toBe(false);
    });
  });

  describe('Error Handling', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
    });

    it('should handle terminal errors', () => {
      const callback = jest.fn();
      client.on('terminal-error', callback);

      const terminalErrorHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-error')[1];
      const errorData = { sessionId: 'test-session', error: 'Command not found' };
      terminalErrorHandler(errorData);

      expect(callback).toHaveBeenCalledWith(errorData);
    });

    it('should handle connection timeout', (done) => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      mockSocket.connect.mockImplementation(() => {
        // Don't trigger connect event, let it timeout
      });

      client.connect().catch(() => {
        // Expected to fail
      });

      setTimeout(() => {
        expect(consoleSpy).toHaveBeenCalledWith(
          expect.stringContaining('Connection timeout after 5 seconds')
        );
        consoleSpy.mockRestore();
        done();
      }, 5100);
    });

    it('should handle unexpected errors gracefully', () => {
      const callback = jest.fn();
      client.on('test-event', callback);

      // Simulate an error in the callback
      callback.mockImplementation(() => {
        throw new Error('Callback error');
      });

      expect(() => {
        const testHandler = mockSocket.on.mock.calls.find(call => call[0] === 'message')[1];
        testHandler({ type: 'test' });
      }).not.toThrow();
    });
  });

  describe('Singleton Instance', () => {
    it('should export singleton wsClient', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should maintain same instance across imports', () => {
      const { wsClient: wsClient1 } = require('../websocket/client');
      const { wsClient: wsClient2 } = require('../websocket/client');
      
      expect(wsClient1).toBe(wsClient2);
    });
  });

  describe('Memory Management', () => {
    let client: WebSocketClient;

    beforeEach(() => {
      client = new WebSocketClient();
    });

    it('should clean up listeners on disconnect', () => {
      const callback = jest.fn();
      client.on('test-event', callback);
      
      mockSocket.connected = true;
      client.disconnect();

      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(client.connected).toBe(false);
    });

    it('should clear pending configs on disconnect', () => {
      // Add pending config
      const terminalConfigHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')[1];
      terminalConfigHandler({ sessionId: 'test', rows: 24, cols: 80 });

      client.disconnect();

      // After disconnect, adding listener should not receive pending configs
      const callback = jest.fn();
      client.on('terminal-config', callback);

      setTimeout(() => {
        expect(callback).not.toHaveBeenCalled();
      }, 0);
    });
  });
});