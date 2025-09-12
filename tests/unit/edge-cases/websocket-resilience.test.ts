/**
 * WebSocket Resilience and Edge Case Tests
 * Tests error handling, edge conditions, and fault tolerance
 */

import WebSocketClient from '@/lib/websocket/client';
import type { WebSocketMessage } from '@/types';

// Mock Socket.IO for error simulation
const mockSocket = {
  connected: false,
  id: 'mock-socket',
  on: jest.fn(),
  off: jest.fn(),
  emit: jest.fn(),
  connect: jest.fn(),
  disconnect: jest.fn(),
  removeAllListeners: jest.fn()
};

const mockIo = jest.fn(() => mockSocket);

jest.mock('socket.io-client', () => ({
  io: mockIo
}));

describe('WebSocket Resilience Tests', () => {
  let client: WebSocketClient;
  
  beforeEach(() => {
    client = new WebSocketClient();
    jest.clearAllMocks();
    mockSocket.connected = false;
  });

  afterEach(() => {
    client.disconnect();
  });

  describe('Connection Error Handling', () => {
    it('should handle connection timeout gracefully', async () => {
      // Mock connection that never resolves
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect_error') {
          setTimeout(() => callback(new Error('Connection timeout')), 10);
        }
      });

      await expect(client.connect()).rejects.toThrow('Connection timeout');
      expect(client.connected).toBe(false);
      expect(client.connecting).toBe(false);
    });

    it('should handle network disconnection during connection', async () => {
      let connectCallback: Function;
      let disconnectCallback: Function;

      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') connectCallback = callback;
        if (event === 'disconnect') disconnectCallback = callback;
      });

      const connectPromise = client.connect();
      
      // Simulate connection then immediate disconnection
      setTimeout(() => {
        mockSocket.connected = true;
        connectCallback?.();
        
        setTimeout(() => {
          mockSocket.connected = false;
          disconnectCallback?.('transport close');
        }, 5);
      }, 5);

      await connectPromise;
      
      // Should handle the disconnection gracefully
      expect(client.connecting).toBe(false);
    });

    it('should handle invalid WebSocket URL', () => {
      const invalidClient = new WebSocketClient('invalid-url');
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect_error') {
          callback(new Error('Invalid URL'));
        }
      });

      expect(invalidClient.connect()).rejects.toThrow();
    });
  });

  describe('Message Handling Edge Cases', () => {
    beforeEach(async () => {
      mockSocket.connected = true;
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') callback();
      });
      await client.connect();
    });

    it('should handle malformed messages gracefully', () => {
      const messageCallback = jest.fn();
      client.on('message', messageCallback);

      // Simulate receiving malformed message
      const malformedMessages = [
        null,
        undefined,
        '',
        { type: null },
        { data: 'test' }, // missing type
        { type: 'data' }, // missing required fields
        { type: 'data', data: null },
        'not an object'
      ];

      malformedMessages.forEach(msg => {
        // Should not throw when receiving malformed messages
        expect(() => {
          (client as any).emit('message', msg);
        }).not.toThrow();
      });
    });

    it('should handle extremely large messages', () => {
      const largeData = 'x'.repeat(1024 * 1024 * 5); // 5MB
      
      const message: WebSocketMessage = {
        type: 'data',
        sessionId: 'test',
        data: largeData,
        timestamp: Date.now()
      };

      expect(() => {
        client.sendMessage(message);
      }).not.toThrow();

      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('should handle rapid message bursts', () => {
      const messageCount = 10000;
      const messages: WebSocketMessage[] = [];

      // Generate burst of messages
      for (let i = 0; i < messageCount; i++) {
        messages.push({
          type: 'data',
          sessionId: `session-${i % 10}`,
          data: `Message ${i}`,
          timestamp: Date.now()
        });
      }

      // Should handle sending all messages without error
      expect(() => {
        messages.forEach(msg => client.sendMessage(msg));
      }).not.toThrow();

      expect(mockSocket.emit).toHaveBeenCalledTimes(messageCount);
    });
  });

  describe('State Management Edge Cases', () => {
    it('should handle disconnect while connecting', async () => {
      let connectCallback: Function;
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') connectCallback = callback;
      });

      // Start connection
      const connectPromise = client.connect();
      
      // Disconnect immediately while connecting
      client.disconnect();
      
      // Complete the connection after disconnect
      setTimeout(() => {
        mockSocket.connected = true;
        connectCallback?.();
      }, 5);

      // Connection should still resolve but client should be disconnected
      await connectPromise;
      expect(client.connected).toBe(false);
    });

    it('should handle multiple simultaneous connection attempts', async () => {
      let connectionCount = 0;
      
      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') {
          connectionCount++;
          setTimeout(() => {
            mockSocket.connected = true;
            callback();
          }, 10);
        }
      });

      // Start multiple connections simultaneously
      const connections = [
        client.connect(),
        client.connect(),
        client.connect()
      ];

      await Promise.all(connections);
      
      // Should only establish one actual connection
      expect(connectionCount).toBe(1);
      expect(client.connected).toBe(true);
    });

    it('should handle listener operations on disconnected client', () => {
      const callback = jest.fn();
      
      // Add listener to disconnected client
      expect(() => {
        client.on('test-event', callback);
      }).not.toThrow();

      // Remove listener from disconnected client
      expect(() => {
        client.off('test-event', callback);
      }).not.toThrow();

      // Emit to disconnected client
      expect(() => {
        (client as any).emit('test-event', { data: 'test' });
      }).not.toThrow();

      expect(callback).toHaveBeenCalledWith({ data: 'test' });
    });
  });

  describe('Memory and Resource Edge Cases', () => {
    it('should handle listener removal during event emission', () => {
      const callbacks: Function[] = [];
      let emissionCount = 0;

      // Create listeners that remove themselves during execution
      for (let i = 0; i < 5; i++) {
        const callback = jest.fn(() => {
          emissionCount++;
          // Remove self after first call
          client.off('self-removing', callback);
        });
        callbacks.push(callback);
        client.on('self-removing', callback);
      }

      // Emit event
      (client as any).emit('self-removing', { test: 'data' });

      // All callbacks should have been called once
      expect(emissionCount).toBe(5);
      callbacks.forEach(callback => {
        expect(callback).toHaveBeenCalledTimes(1);
      });

      // Emit again - no callbacks should be called
      (client as any).emit('self-removing', { test: 'data' });
      expect(emissionCount).toBe(5); // No increase
    });

    it('should handle circular reference in message data', () => {
      const circularObj: any = { name: 'test' };
      circularObj.self = circularObj;

      const message: WebSocketMessage = {
        type: 'data',
        sessionId: 'test',
        data: circularObj,
        timestamp: Date.now()
      };

      // Should handle circular references gracefully
      expect(() => {
        client.sendMessage(message);
      }).not.toThrow();
    });

    it('should handle extremely deep object nesting', () => {
      // Create deeply nested object
      let deepObj: any = {};
      let current = deepObj;
      for (let i = 0; i < 1000; i++) {
        current.next = {};
        current = current.next;
      }
      current.value = 'deep value';

      const message: WebSocketMessage = {
        type: 'data',
        sessionId: 'test',
        data: deepObj,
        timestamp: Date.now()
      };

      expect(() => {
        client.sendMessage(message);
      }).not.toThrow();
    });
  });

  describe('Error Recovery', () => {
    it('should recover from temporary connection loss', async () => {
      let connectCallback: Function;
      let disconnectCallback: Function;
      let reconnectCallback: Function;

      mockSocket.on.mockImplementation((event, callback) => {
        if (event === 'connect') connectCallback = callback;
        if (event === 'disconnect') disconnectCallback = callback;
        if (event === 'reconnect') reconnectCallback = callback;
      });

      // Initial connection
      const initialConnect = client.connect();
      mockSocket.connected = true;
      connectCallback?.();
      await initialConnect;

      expect(client.connected).toBe(true);

      // Simulate disconnection
      mockSocket.connected = false;
      disconnectCallback?.('transport close');

      // Simulate reconnection
      setTimeout(() => {
        mockSocket.connected = true;
        reconnectCallback?.();
      }, 100);

      // Client should handle the reconnection
      expect(client.connecting).toBe(false);
    });

    it('should handle socket cleanup errors', () => {
      mockSocket.removeAllListeners.mockImplementation(() => {
        throw new Error('Cleanup error');
      });

      // Should not throw even if cleanup fails
      expect(() => {
        client.disconnect();
      }).not.toThrow();
    });
  });

  describe('Boundary Conditions', () => {
    it('should handle maximum listener count', () => {
      const maxListeners = 1000;
      const callbacks: Function[] = [];

      // Add maximum number of listeners
      for (let i = 0; i < maxListeners; i++) {
        const callback = jest.fn();
        callbacks.push(callback);
        client.on(`event-${i % 10}`, callback);
      }

      // Should handle emission to all listeners
      expect(() => {
        for (let i = 0; i < 10; i++) {
          (client as any).emit(`event-${i}`, { data: i });
        }
      }).not.toThrow();

      // Verify appropriate callbacks were called
      callbacks.forEach((callback, index) => {
        const eventIndex = index % 10;
        expect(callback).toHaveBeenCalledWith({ data: eventIndex });
      });
    });

    it('should handle zero-length and empty data', () => {
      const emptyMessages = [
        { type: 'data', sessionId: 'test', data: '', timestamp: Date.now() },
        { type: 'data', sessionId: '', data: 'test', timestamp: Date.now() },
        { type: '', sessionId: 'test', data: 'test', timestamp: Date.now() },
        { type: 'data', sessionId: 'test', data: null, timestamp: Date.now() },
        { type: 'data', sessionId: 'test', data: undefined, timestamp: Date.now() }
      ];

      emptyMessages.forEach(msg => {
        expect(() => {
          client.sendMessage(msg as WebSocketMessage);
        }).not.toThrow();
      });
    });
  });
});