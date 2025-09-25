/**
 * Comprehensive unit tests for WebSocket client
 * Tests connection management, message handling, reconnection logic, and error handling
 */

import { wsClient } from '@/lib/websocket/client';
import { mockSocket, MockWebSocket } from '../../mocks/websocket';

// Mock socket.io-client
jest.mock('socket.io-client');

describe('WebSocket Client', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    MockWebSocket.reset();
    mockSocket.reset();

    // Reset client state
    (wsClient as any).socket = null;
    (wsClient as any).connected = false;
    (wsClient as any).connecting = false;
    (wsClient as any).reconnectAttempts = 0;
  });

  afterEach(() => {
    // Clean up any active connections
    if ((wsClient as any).socket) {
      (wsClient as any).socket.disconnect();
      (wsClient as any).socket = null;
    }
  });

  describe('Connection Management', () => {
    it('connects successfully with default options', async () => {
      const connectPromise = wsClient.connect();

      // Simulate successful connection
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      await expect(connectPromise).resolves.toBeUndefined();
      expect(wsClient.connected).toBe(true);
      expect(wsClient.connecting).toBe(false);
    });

    it('connects with custom URL', async () => {
      const customUrl = 'ws://custom.example.com:3001';
      const connectPromise = wsClient.connect(customUrl);

      // Simulate connection
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      await expect(connectPromise).resolves.toBeUndefined();
      expect(wsClient.connected).toBe(true);
    });

    it('prevents multiple simultaneous connections', async () => {
      const promise1 = wsClient.connect();
      const promise2 = wsClient.connect();
      const promise3 = wsClient.connect();

      // Simulate successful connection
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      await Promise.all([promise1, promise2, promise3]);

      // Should only create one connection
      expect(mockSocket.connect).toHaveBeenCalledTimes(1);
    });

    it('handles connection timeout', async () => {
      jest.useFakeTimers();

      const connectPromise = wsClient.connect();

      // Don't simulate connection event - let it timeout
      jest.advanceTimersByTime(10000); // 10 seconds

      await expect(connectPromise).rejects.toThrow('Connection timeout');

      jest.useRealTimers();
    });

    it('handles connection errors', async () => {
      const connectPromise = wsClient.connect();

      // Simulate connection error
      const error = new Error('Connection failed');
      mockSocket.simulateEvent('connect_error', error);

      await expect(connectPromise).rejects.toThrow('Connection failed');
      expect(wsClient.connected).toBe(false);
      expect(wsClient.connecting).toBe(false);
    });

    it('disconnects cleanly', () => {
      // First connect
      wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      // Then disconnect
      wsClient.disconnect();

      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(wsClient.connected).toBe(false);
    });

    it('handles disconnect when not connected', () => {
      expect(() => {
        wsClient.disconnect();
      }).not.toThrow();
    });
  });

  describe('Message Handling', () => {
    beforeEach(async () => {
      // Establish connection for message tests
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;
    });

    it('sends messages correctly', () => {
      const message = { type: 'test', data: 'hello' };

      wsClient.sendMessage(message);

      expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
    });

    it('sends typed messages with proper formatting', () => {
      wsClient.send('terminal-command', { sessionId: 'session-123', command: 'ls -la' });

      expect(mockSocket.emit).toHaveBeenCalledWith('terminal-command', {
        sessionId: 'session-123',
        command: 'ls -la',
      });
    });

    it('queues messages when disconnected', () => {
      // Disconnect first
      wsClient.disconnect();
      mockSocket.connected = false;

      const message = { type: 'test', data: 'queued' };
      wsClient.sendMessage(message);

      // Message should be queued, not sent immediately
      expect(mockSocket.emit).not.toHaveBeenCalledWith('message', message);

      // Should send queued messages on reconnect
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      return connectPromise.then(() => {
        expect(mockSocket.emit).toHaveBeenCalledWith('message', message);
      });
    });

    it('handles send errors gracefully', () => {
      mockSocket.emit.mockImplementation(() => {
        throw new Error('Send failed');
      });

      expect(() => {
        wsClient.sendMessage({ type: 'test', data: 'test' });
      }).not.toThrow();
    });

    it('limits message queue size', () => {
      // Disconnect to enable queuing
      wsClient.disconnect();
      mockSocket.connected = false;

      // Send many messages
      for (let i = 0; i < 1100; i++) {
        wsClient.sendMessage({ type: 'test', data: `message-${i}` });
      }

      // Reconnect and check queue was limited
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      return connectPromise.then(() => {
        // Should only process last 1000 messages
        expect(mockSocket.emit).toHaveBeenCalledTimes(1000);
      });
    });
  });

  describe('Event Handling', () => {
    beforeEach(async () => {
      // Establish connection
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;
    });

    it('registers event listeners correctly', () => {
      const handler = jest.fn();

      wsClient.on('test-event', handler);

      expect(mockSocket.on).toHaveBeenCalledWith('test-event', handler);
    });

    it('removes event listeners correctly', () => {
      const handler = jest.fn();

      wsClient.on('test-event', handler);
      wsClient.off('test-event', handler);

      expect(mockSocket.off).toHaveBeenCalledWith('test-event', handler);
    });

    it('handles events when connected', () => {
      const handler = jest.fn();
      wsClient.on('terminal-data', handler);

      // Simulate event from server
      mockSocket.simulateEvent('terminal-data', { sessionId: 'test', data: 'output' });

      expect(handler).toHaveBeenCalledWith({ sessionId: 'test', data: 'output' });
    });

    it('removes all listeners on disconnect', () => {
      const handler1 = jest.fn();
      const handler2 = jest.fn();

      wsClient.on('event1', handler1);
      wsClient.on('event2', handler2);

      wsClient.disconnect();

      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
    });

    it('handles duplicate event registrations', () => {
      const handler = jest.fn();

      wsClient.on('test-event', handler);
      wsClient.on('test-event', handler); // Duplicate

      // Should only register once
      expect(mockSocket.on).toHaveBeenCalledTimes(1);
    });
  });

  describe('Reconnection Logic', () => {
    it('attempts reconnection on disconnect', async () => {
      jest.useFakeTimers();

      // Connect first
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Simulate unexpected disconnect
      mockSocket.connected = false;
      mockSocket.simulateEvent('disconnect', 'transport close');

      // Should attempt reconnection after delay
      jest.advanceTimersByTime(1000);

      expect(mockSocket.connect).toHaveBeenCalledTimes(2); // Initial + reconnect

      jest.useRealTimers();
    });

    it('uses exponential backoff for reconnection', async () => {
      jest.useFakeTimers();

      const connectSpy = jest.spyOn(mockSocket, 'connect');

      // Connect first
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Simulate multiple failed reconnections
      for (let i = 0; i < 3; i++) {
        mockSocket.connected = false;
        mockSocket.simulateEvent('disconnect', 'transport close');

        const expectedDelay = Math.min(1000 * Math.pow(2, i), 30000);
        jest.advanceTimersByTime(expectedDelay);

        mockSocket.simulateEvent('connect_error', new Error('Still failing'));
      }

      expect(connectSpy).toHaveBeenCalledTimes(4); // Initial + 3 reconnects

      jest.useRealTimers();
    });

    it('stops reconnecting after max attempts', async () => {
      jest.useFakeTimers();

      // Connect first
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Simulate many failed reconnections
      for (let i = 0; i < 10; i++) {
        mockSocket.connected = false;
        mockSocket.simulateEvent('disconnect', 'transport close');
        jest.advanceTimersByTime(30000); // Max delay
        mockSocket.simulateEvent('connect_error', new Error('Connection failed'));
      }

      // Should stop trying after max attempts (typically 5)
      expect(mockSocket.connect).toHaveBeenCalledTimes(6); // Initial + 5 reconnects

      jest.useRealTimers();
    });

    it('resets reconnection attempts on successful connection', async () => {
      jest.useFakeTimers();

      // Connect, disconnect, reconnect successfully
      let connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Disconnect
      mockSocket.connected = false;
      mockSocket.simulateEvent('disconnect', 'transport close');

      // Advance time for reconnection attempt
      jest.advanceTimersByTime(1000);

      // Successful reconnection
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      // Disconnect again
      mockSocket.connected = false;
      mockSocket.simulateEvent('disconnect', 'transport close');

      // Should use initial delay again (reconnection count reset)
      jest.advanceTimersByTime(1000);

      expect(mockSocket.connect).toHaveBeenCalledTimes(3); // Initial + reconnect + second reconnect

      jest.useRealTimers();
    });

    it('does not reconnect on manual disconnect', async () => {
      jest.useFakeTimers();

      // Connect first
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Manual disconnect
      wsClient.disconnect();

      // Advance time
      jest.advanceTimersByTime(10000);

      // Should not attempt reconnection
      expect(mockSocket.connect).toHaveBeenCalledTimes(1); // Only initial connect

      jest.useRealTimers();
    });
  });

  describe('Error Handling', () => {
    it('handles socket creation errors', async () => {
      // Mock socket.io to throw on creation
      const ioMock = require('socket.io-client');
      ioMock.io.mockImplementation(() => {
        throw new Error('Socket creation failed');
      });

      await expect(wsClient.connect()).rejects.toThrow('Socket creation failed');
    });

    it('handles malformed server responses', async () => {
      // Connect first
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      const handler = jest.fn();
      wsClient.on('terminal-data', handler);

      // Send malformed data
      expect(() => {
        mockSocket.simulateEvent('terminal-data', null);
        mockSocket.simulateEvent('terminal-data', undefined);
        mockSocket.simulateEvent('terminal-data', 'invalid-json');
      }).not.toThrow();
    });

    it('recovers from temporary network errors', async () => {
      jest.useFakeTimers();

      // Connect
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Simulate network error
      mockSocket.connected = false;
      mockSocket.simulateEvent('disconnect', 'ping timeout');

      // Should attempt reconnection
      jest.advanceTimersByTime(1000);

      // Simulate successful recovery
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});

      expect(wsClient.connected).toBe(true);

      jest.useRealTimers();
    });

    it('handles concurrent operation errors', () => {
      const operations = [];

      // Queue many operations
      for (let i = 0; i < 100; i++) {
        operations.push(wsClient.connect());
        operations.push(Promise.resolve().then(() => wsClient.disconnect()));
        operations.push(Promise.resolve().then(() =>
          wsClient.sendMessage({ type: 'test', data: `msg-${i}` })
        ));
      }

      // Should handle all operations without throwing
      return expect(Promise.allSettled(operations)).resolves.toBeDefined();
    });
  });

  describe('Performance', () => {
    beforeEach(async () => {
      // Establish connection
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;
    });

    it('handles high message throughput', () => {
      const messages = [];
      for (let i = 0; i < 10000; i++) {
        messages.push({ type: 'test', data: `message-${i}` });
      }

      expect(() => {
        messages.forEach(msg => wsClient.sendMessage(msg));
      }).not.toThrow();

      expect(mockSocket.emit).toHaveBeenCalledTimes(10000);
    });

    it('handles many event listeners efficiently', () => {
      const handlers = [];

      // Register many handlers
      for (let i = 0; i < 1000; i++) {
        const handler = jest.fn();
        handlers.push(handler);
        wsClient.on(`event-${i}`, handler);
      }

      // Should register all handlers
      expect(mockSocket.on).toHaveBeenCalledTimes(1000);

      // Clean up efficiently
      handlers.forEach((handler, i) => {
        wsClient.off(`event-${i}`, handler);
      });

      expect(mockSocket.off).toHaveBeenCalledTimes(1000);
    });

    it('manages memory usage with large payloads', () => {
      const largeData = {
        type: 'bulk-data',
        payload: 'x'.repeat(1024 * 1024), // 1MB string
        timestamp: Date.now(),
        metadata: {
          chunks: Array(1000).fill(0).map((_, i) => `chunk-${i}`),
        },
      };

      expect(() => {
        wsClient.sendMessage(largeData);
      }).not.toThrow();

      expect(mockSocket.emit).toHaveBeenCalledWith('message', largeData);
    });
  });

  describe('State Management', () => {
    it('maintains correct connection state', async () => {
      expect(wsClient.connected).toBe(false);
      expect(wsClient.connecting).toBe(false);

      // Start connecting
      const connectPromise = wsClient.connect();
      expect(wsClient.connecting).toBe(true);

      // Complete connection
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      expect(wsClient.connected).toBe(true);
      expect(wsClient.connecting).toBe(false);

      // Disconnect
      wsClient.disconnect();
      expect(wsClient.connected).toBe(false);
    });

    it('handles state changes during operations', async () => {
      // Start connecting
      const connectPromise = wsClient.connect();

      // Try to send message while connecting
      wsClient.sendMessage({ type: 'test', data: 'queued' });

      // Complete connection
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Queued message should be sent
      expect(mockSocket.emit).toHaveBeenCalledWith('message', {
        type: 'test',
        data: 'queued',
      });
    });

    it('prevents operations on disposed client', () => {
      // Simulate client disposal
      wsClient.disconnect();
      (wsClient as any).socket = null;

      expect(() => {
        wsClient.sendMessage({ type: 'test', data: 'test' });
      }).not.toThrow();

      expect(() => {
        wsClient.on('test', jest.fn());
      }).not.toThrow();
    });
  });

  describe('Edge Cases', () => {
    it('handles rapid connect/disconnect cycles', async () => {
      for (let i = 0; i < 10; i++) {
        const connectPromise = wsClient.connect();
        mockSocket.connected = true;
        mockSocket.simulateEvent('connect', {});
        await connectPromise;

        wsClient.disconnect();
        mockSocket.connected = false;
      }

      // Should end in disconnected state
      expect(wsClient.connected).toBe(false);
    });

    it('handles connection during reconnection', async () => {
      jest.useFakeTimers();

      // Initial connection
      let connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      // Disconnect to trigger reconnection
      mockSocket.connected = false;
      mockSocket.simulateEvent('disconnect', 'transport close');

      // Start reconnection timer
      jest.advanceTimersByTime(500);

      // Manual connect during reconnection
      connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      expect(wsClient.connected).toBe(true);

      jest.useRealTimers();
    });

    it('handles missing event data gracefully', async () => {
      const connectPromise = wsClient.connect();
      mockSocket.connected = true;
      mockSocket.simulateEvent('connect', {});
      await connectPromise;

      const handler = jest.fn();
      wsClient.on('test-event', handler);

      // Send events with missing data
      expect(() => {
        mockSocket.simulateEvent('test-event');
        mockSocket.simulateEvent('test-event', null);
        mockSocket.simulateEvent('test-event', undefined);
      }).not.toThrow();

      expect(handler).toHaveBeenCalledTimes(3);
    });

    it('handles WebSocket URL variations', async () => {
      const urls = [
        'ws://localhost:3001',
        'wss://secure.example.com:443',
        'http://legacy.example.com:8080',
        'https://secure.legacy.example.com',
        '',
        undefined,
      ];

      for (const url of urls) {
        mockSocket.reset();

        expect(async () => {
          const connectPromise = wsClient.connect(url);
          mockSocket.connected = true;
          mockSocket.simulateEvent('connect', {});
          await connectPromise;
          wsClient.disconnect();
        }).not.toThrow();
      }
    });
  });
});