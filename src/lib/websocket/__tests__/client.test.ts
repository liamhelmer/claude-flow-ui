/**
 * Comprehensive Test Suite for WebSocket Client
 * Testing connection management, message handling, error recovery, and edge cases
 */

import WebSocketClient, { wsClient } from '../client';
import type { WebSocketMessage } from '@/types';

// Mock Socket.IO using Jest module mocking approach
const mockSocket = {
  connected: false,
  id: 'mock-socket-id',
  connect: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  removeAllListeners: jest.fn(),
};

const mockIo = jest.fn(() => mockSocket);

// Mock socket.io-client before any imports
jest.mock('socket.io-client', () => {
  const mockSocket = {
    connected: false,
    id: 'mock-socket-id',
    connect: jest.fn(),
    disconnect: jest.fn(),
    emit: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
    removeAllListeners: jest.fn(),
  };
  
  const mockIo = jest.fn(() => mockSocket);
  
  return {
    io: mockIo,
    Socket: jest.fn(),
  };
});

// Mock window for port detection
delete (window as any).location;
(window as any).location = {
  port: '3000',
  hostname: 'localhost',
  protocol: 'http:',
};

describe('WebSocketClient', () => {
  let client: WebSocketClient;
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset mock socket state
    const { io } = require('socket.io-client');
    const mockSocketInstance = io();
    
    mockSocketInstance.connected = false;
    mockSocketInstance.on.mockClear();
    mockSocketInstance.emit.mockClear();
    mockSocketInstance.connect.mockClear();
    mockSocketInstance.disconnect.mockClear();
    mockSocketInstance.removeAllListeners.mockClear();
    
    client = new WebSocketClient();
    consoleSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    client.disconnect();
  });

  describe('Constructor and URL Calculation', () => {
    it('should calculate WebSocket URL from window port', () => {
      const client = new WebSocketClient();
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Dynamic port calculation'),
        expect.stringContaining('3000'),
        expect.stringContaining('3001')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Calculated URL:'),
        'ws://localhost:3001'
      );
    });

    it('should use provided URL when specified', () => {
      const customUrl = 'ws://custom-server:8080';
      const client = new WebSocketClient(customUrl);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] Using provided URL:',
        customUrl
      );
    });

    it('should handle missing window port gracefully', () => {
      const originalLocation = window.location;
      Object.defineProperty(window, 'location', {
        value: { port: '' },
        writable: true,
      });

      const client = new WebSocketClient();
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Calculated URL:'),
        'ws://localhost:11236'
      );

      // Restore original location
      Object.defineProperty(window, 'location', { value: originalLocation });
    });

    it('should use environment variable when available', () => {
      const originalEnv = process.env.NEXT_PUBLIC_WS_URL;
      process.env.NEXT_PUBLIC_WS_URL = 'ws://env-server:9999';

      const client = new WebSocketClient();
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Calculated URL:'),
        'ws://env-server:9999'
      );

      // Restore original env
      if (originalEnv) {
        process.env.NEXT_PUBLIC_WS_URL = originalEnv;
      } else {
        delete process.env.NEXT_PUBLIC_WS_URL;
      }
    });
  });

  describe('Connection Management', () => {
    it('should connect successfully', async () => {
      // Mock successful connection
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 10);
        }
      });

      const connectPromise = client.connect();
      
      // Verify connection attempt
      expect(mockIo).toHaveBeenCalledWith('ws://localhost:3001', {
        transports: ['websocket', 'polling'],
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
      });

      await connectPromise;
      
      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] Successfully connected! Socket ID:',
        'mock-socket-id'
      );
    });

    it('should handle connection errors', async () => {
      const connectionError = new Error('Connection refused');
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect_error') {
          setTimeout(() => callback(connectionError), 10);
        }
      });

      await expect(client.connect()).rejects.toThrow('Connection refused');
      
      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] Connection error:',
        'Connection refused',
        'URL:',
        'ws://localhost:3001'
      );
    });

    it('should not attempt to connect if already connected', async () => {
      mockSocket.connected = true;
      
      await client.connect();
      
      expect(mockIo).not.toHaveBeenCalled();
    });

    it('should wait for existing connection attempt', async () => {
      let connectCallback: Function;
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      
      mockSocketInstance.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          connectCallback = () => {
            mockSocketInstance.connected = true;
            callback();
          };
        }
      });

      // Start first connection
      const firstConnect = client.connect();
      
      // Start second connection immediately
      const secondConnect = client.connect();
      
      // Complete the connection
      setTimeout(() => connectCallback(), 50);
      
      await Promise.all([firstConnect, secondConnect]);
      
      // Should only create one socket instance
      expect(io).toHaveBeenCalledTimes(1);
    });

    it('should handle connection timeout', async () => {
      jest.useFakeTimers();
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      
      mockSocketInstance.on.mockImplementation(() => {
        // Never connect
      });

      const connectPromise = client.connect();
      
      // Fast-forward past timeout
      jest.advanceTimersByTime(5000);
      
      expect(warnSpy).toHaveBeenCalledWith(
        '[WebSocket] Connection timeout after 5 seconds to:',
        'ws://localhost:3001'
      );

      warnSpy.mockRestore();
      jest.useRealTimers();
    });

    it('should handle disconnection events', () => {
      let disconnectCallback: Function;
      
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      
      mockSocketInstance.on.mockImplementation((event, callback) => {
        if (event === 'disconnect') {
          disconnectCallback = callback;
        }
      });

      client.connect();
      
      // Simulate disconnection
      disconnectCallback('transport close');
      
      expect(consoleSpy).toHaveBeenCalledWith(
        '[WebSocket] Disconnected:',
        'transport close'
      );
    });

    it('should disconnect properly', () => {
      client.disconnect();
      
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      
      expect(mockSocketInstance.removeAllListeners).toHaveBeenCalled();
      expect(mockSocketInstance.disconnect).toHaveBeenCalled();
    });
  });

  describe('Message Handling', () => {
    beforeEach(async () => {
      // Setup connected socket
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      mockSocketInstance.connected = true;
      
      mockSocketInstance.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          setTimeout(callback, 10);
        }
      });
      
      client['socket'] = mockSocketInstance;
      await client.connect();
    });

    it('should send messages when connected', () => {
      const message: WebSocketMessage = {
        type: 'test',
        data: { content: 'test message' },
      };

      client.sendMessage(message);
      
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      expect(mockSocketInstance.emit).toHaveBeenCalledWith('message', message);
    });

    it('should send event data when connected', () => {
      client.send('custom-event', { data: 'test' });
      
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      expect(mockSocketInstance.emit).toHaveBeenCalledWith('custom-event', { data: 'test' });
    });

    it('should warn when sending while disconnected', () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const { io } = require('socket.io-client');
      const mockSocketInstance = io();
      mockSocketInstance.connected = false;
      client['socket'] = mockSocketInstance;
      
      client.send('test-event', {});
      
      expect(warnSpy).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send message'
      );
      expect(mockSocketInstance.emit).not.toHaveBeenCalled();
      
      warnSpy.mockRestore();
    });

    it('should route terminal events correctly', () => {
      const eventCallbacks: Record<string, Function> = {};
      
      mockSocket.on.mockImplementation((event, callback) => {
        eventCallbacks[event] = callback;
      });

      // Reconnect to register event handlers
      client.connect();
      
      const dataHandler = jest.fn();
      client.on('terminal-data', dataHandler);
      
      // Simulate terminal data event
      eventCallbacks['terminal-data']({ sessionId: 'test', data: 'output' });
      
      expect(dataHandler).toHaveBeenCalledWith({ sessionId: 'test', data: 'output' });
    });

    it('should handle all terminal event types', () => {
      const eventCallbacks: Record<string, Function> = {};
      const handlers: Record<string, jest.Mock> = {};
      
      mockSocket.on.mockImplementation((event, callback) => {
        eventCallbacks[event] = callback;
      });

      client.connect();
      
      // Register handlers for all event types
      const eventTypes = [
        'message',
        'terminal-data',
        'terminal-resize',
        'terminal-config',
        'terminal-error',
        'connection-change',
        'session-created',
        'session-destroyed',
      ];
      
      eventTypes.forEach(eventType => {
        handlers[eventType] = jest.fn();
        client.on(eventType, handlers[eventType]);
      });
      
      // Trigger all events
      eventTypes.forEach(eventType => {
        const testData = { event: eventType, test: true };
        eventCallbacks[eventType](testData);
        expect(handlers[eventType]).toHaveBeenCalledWith(testData);
      });
    });
  });

  describe('Event System', () => {
    it('should register and trigger event listeners', () => {
      const handler = jest.fn();
      
      client.on('test-event', handler);
      
      // Manually trigger event through emit method
      (client as any).emit('test-event', { data: 'test' });
      
      expect(handler).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should remove event listeners', () => {
      const handler = jest.fn();
      
      client.on('test-event', handler);
      client.off('test-event', handler);
      
      (client as any).emit('test-event', { data: 'test' });
      
      expect(handler).not.toHaveBeenCalled();
    });

    it('should handle multiple listeners for same event', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();
      
      client.on('test-event', handler1);
      client.on('test-event', handler2);
      
      (client as any).emit('test-event', { data: 'test' });
      
      expect(handler1).toHaveBeenCalledWith({ data: 'test' });
      expect(handler2).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should warn about excessive listeners', () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Add 11 listeners to trigger warning
      for (let i = 0; i < 11; i++) {
        client.on('test-event', jest.fn());
      }
      
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('MaxListenersExceededWarning')
      );
      
      warnSpy.mockRestore();
    });

    it('should clear all listeners on disconnect', () => {
      const handler = jest.fn();
      client.on('test-event', handler);
      
      client.disconnect();
      
      (client as any).emit('test-event', { data: 'test' });
      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('Connection State', () => {
    it('should report connected status correctly', () => {
      mockSocket.connected = false;
      expect(client.connected).toBe(false);
      
      mockSocket.connected = true;
      expect(client.connected).toBe(true);
    });

    it('should report connecting status correctly', () => {
      expect(client.connecting).toBe(false);
      
      // Start connection (sets isConnecting to true)
      mockSocket.on.mockImplementation(() => {
        // Don't complete connection
      });
      
      client.connect();
      expect(client.connecting).toBe(true);
    });

    it('should handle null socket gracefully', () => {
      client.disconnect(); // This sets socket to null
      
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });
  });

  describe('Error Recovery and Resilience', () => {
    it('should handle reconnection scenarios', async () => {
      let connectCallback: Function;
      let disconnectCallback: Function;
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          connectCallback = () => {
            mockSocket.connected = true;
            callback();
          };
        } else if (event === 'disconnect') {
          disconnectCallback = callback;
        }
      });

      // Initial connection
      const connectPromise = client.connect();
      connectCallback();
      await connectPromise;
      
      expect(client.connected).toBe(true);
      
      // Simulate disconnection
      mockSocket.connected = false;
      disconnectCallback('transport error');
      
      expect(client.connecting).toBe(false);
      
      // Reconnect
      mockSocket.connected = true;
      connectCallback();
      
      expect(client.connected).toBe(true);
    });

    it('should handle network interruption during send', () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Start connected
      mockSocket.connected = true;
      
      // Simulate network interruption
      mockSocket.connected = false;
      
      client.send('test', { data: 'test' });
      
      expect(warnSpy).toHaveBeenCalledWith(
        'WebSocket not connected, cannot send message'
      );
      
      warnSpy.mockRestore();
    });

    it('should handle socket creation errors', async () => {
      const socketError = new Error('Socket creation failed');
      mockIo.mockImplementationOnce(() => {
        throw socketError;
      });

      await expect(client.connect()).rejects.toThrow('Socket creation failed');
    });

    it('should handle malformed event data', () => {
      const handler = jest.fn();
      client.on('test-event', handler);
      
      // Send various malformed data types
      (client as any).emit('test-event', null);
      (client as any).emit('test-event', undefined);
      (client as any).emit('test-event', { circular: {} });
      
      expect(handler).toHaveBeenCalledTimes(3);
    });

    it('should handle rapid connect/disconnect cycles', async () => {
      let connectCallback: Function;
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          connectCallback = () => {
            mockSocket.connected = true;
            callback();
          };
        }
      });

      // Rapid connect/disconnect cycles
      for (let i = 0; i < 5; i++) {
        const connectPromise = client.connect();
        connectCallback();
        await connectPromise;
        
        client.disconnect();
        mockSocket.connected = false;
      }
      
      // Should handle gracefully without errors
      expect(client.connected).toBe(false);
    });

    it('should handle concurrent connection attempts', async () => {
      let connectCallback: Function;
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          connectCallback = () => {
            mockSocket.connected = true;
            callback();
          };
        }
      });

      // Start multiple concurrent connections
      const promises = [
        client.connect(),
        client.connect(),
        client.connect(),
      ];
      
      // Complete connection
      setTimeout(() => connectCallback(), 10);
      
      const results = await Promise.allSettled(promises);
      
      // All should succeed
      expect(results.every(r => r.status === 'fulfilled')).toBe(true);
      expect(mockIo).toHaveBeenCalledTimes(1); // Only one socket created
    });
  });

  describe('Test Environment Handling', () => {
    it('should handle test environment connection simulation', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';
      
      const testClient = new WebSocketClient();
      
      const connectPromise = testClient.connect();
      
      // Should simulate connection in test environment
      await expect(connectPromise).resolves.toBeUndefined();
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should handle test environment with real socket when needed', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 10);
        }
      });

      const testClient = new WebSocketClient();
      await testClient.connect();
      
      expect(mockIo).toHaveBeenCalled();
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Memory Management', () => {
    it('should prevent memory leaks from event listeners', () => {
      const handlers: Function[] = [];
      
      // Add many event listeners
      for (let i = 0; i < 100; i++) {
        const handler = jest.fn();
        handlers.push(handler);
        client.on(`event-${i}`, handler);
      }
      
      // Disconnect should clear all listeners
      client.disconnect();
      
      // Trigger events - none should fire
      for (let i = 0; i < 100; i++) {
        (client as any).emit(`event-${i}`, { test: i });
      }
      
      handlers.forEach(handler => {
        expect(handler).not.toHaveBeenCalled();
      });
    });

    it('should handle repeated listener registration/removal', () => {
      const handler = jest.fn();
      
      // Rapidly add and remove listeners
      for (let i = 0; i < 50; i++) {
        client.on('test-event', handler);
        client.off('test-event', handler);
      }
      
      (client as any).emit('test-event', { data: 'test' });
      
      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('Singleton Instance', () => {
    it('should export a singleton instance', () => {
      expect(wsClient).toBeInstanceOf(WebSocketClient);
    });

    it('should maintain state across imports', () => {
      const handler = jest.fn();
      wsClient.on('singleton-test', handler);
      
      // Simulate another module using the singleton
      (wsClient as any).emit('singleton-test', { test: true });
      
      expect(handler).toHaveBeenCalledWith({ test: true });
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle empty event names', () => {
      const handler = jest.fn();
      
      client.on('', handler);
      client.off('', handler);
      
      (client as any).emit('', { data: 'test' });
      
      expect(handler).not.toHaveBeenCalled();
    });

    it('should handle removing non-existent listeners', () => {
      const handler = jest.fn();
      
      // Should not throw when removing non-existent listener
      expect(() => {
        client.off('non-existent', handler);
      }).not.toThrow();
    });

    it('should handle very large message payloads', () => {
      mockSocket.connected = true;
      const largeData = 'x'.repeat(1000000); // 1MB string
      
      expect(() => {
        client.send('large-data', { payload: largeData });
      }).not.toThrow();
      
      expect(mockSocket.emit).toHaveBeenCalledWith('large-data', {
        payload: largeData,
      });
    });

    it('should handle invalid URL formats gracefully', () => {
      expect(() => {
        new WebSocketClient('invalid-url-format');
      }).not.toThrow();
    });

    it('should handle port edge cases', () => {
      // Test maximum port number
      Object.defineProperty(window, 'location', {
        value: { port: '65535' },
        writable: true,
      });

      expect(() => {
        new WebSocketClient();
      }).not.toThrow();
      
      // Test minimum port number  
      Object.defineProperty(window, 'location', {
        value: { port: '1' },
        writable: true,
      });

      expect(() => {
        new WebSocketClient();
      }).not.toThrow();
    });
  });
});