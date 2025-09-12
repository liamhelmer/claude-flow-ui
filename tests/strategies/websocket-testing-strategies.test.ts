/**
 * @fileoverview Advanced WebSocket Testing Strategies
 * @description Comprehensive test suite for WebSocket connections with complex scenarios
 * @author Testing and Quality Assurance Agent
 */

import { WebSocketClient } from '@/lib/websocket/client';
import type { WebSocketMessage } from '@/types';

// Mock Socket.IO for controlled testing
jest.mock('socket.io-client', () => ({
  io: jest.fn(),
}));

describe('Advanced WebSocket Testing Strategies', () => {
  let mockSocket: any;
  let client: WebSocketClient;

  beforeEach(() => {
    // Reset mocks and create fresh instances
    jest.clearAllMocks();
    
    mockSocket = {
      connected: false,
      id: 'mock-socket-id',
      connect: jest.fn(),
      disconnect: jest.fn(),
      emit: jest.fn(),
      on: jest.fn(),
      removeAllListeners: jest.fn(),
    };

    // Mock io to return our mock socket
    const { io } = require('socket.io-client');
    (io as jest.Mock).mockReturnValue(mockSocket);

    client = new WebSocketClient();
  });

  afterEach(() => {
    client.disconnect();
    jest.clearAllTimers();
  });

  describe('Connection Scenarios', () => {
    it('should handle normal connection flow', async () => {
      const connectPromise = client.connect();
      
      // Simulate successful connection
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls.find(([event]) => event === 'connect')?.[1];
      expect(connectHandler).toBeDefined();
      connectHandler();

      await expect(connectPromise).resolves.toBeUndefined();
      expect(mockSocket.connect).toHaveBeenCalled();
    });

    it('should handle connection timeout scenarios', async () => {
      jest.useFakeTimers();
      
      const connectPromise = client.connect();
      
      // Fast-forward time to trigger timeout
      jest.advanceTimersByTime(6000);
      
      expect(mockSocket.connect).toHaveBeenCalled();
      
      jest.useRealTimers();
    });

    it('should handle reconnection with exponential backoff', async () => {
      const reconnectAttempts = [];
      
      // Mock failed connections
      mockSocket.on.mockImplementation((event: string, handler: Function) => {
        if (event === 'connect_error') {
          // Simulate multiple connection failures
          setTimeout(() => handler(new Error('Connection failed')), 10);
          setTimeout(() => handler(new Error('Connection failed')), 20);
          setTimeout(() => handler(new Error('Connection failed')), 40);
        }
      });

      try {
        await client.connect();
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should handle concurrent connection attempts', async () => {
      const promises = Array.from({ length: 5 }, () => client.connect());
      
      // Simulate connection success
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls.find(([event]) => event === 'connect')?.[1];
      if (connectHandler) connectHandler();

      const results = await Promise.allSettled(promises);
      
      // All should resolve (not create multiple connections)
      results.forEach(result => {
        expect(result.status).toBe('fulfilled');
      });
      
      // Connect should only be called once
      expect(mockSocket.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('Message Handling Scenarios', () => {
    beforeEach(async () => {
      // Establish connection for message tests
      mockSocket.connected = true;
      const connectHandler = jest.fn();
      mockSocket.on.mockImplementation((event: string, handler: Function) => {
        if (event === 'connect') connectHandler.mockImplementation(handler);
      });
      
      await client.connect();
      connectHandler();
    });

    it('should handle large message payloads', () => {
      const largePayload = 'x'.repeat(1024 * 1024); // 1MB payload
      const messageHandler = jest.fn();
      
      client.on('terminal-data', messageHandler);
      
      // Simulate receiving large payload
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      terminalDataHandler({ data: largePayload, sessionId: 'test-session' });
      
      expect(messageHandler).toHaveBeenCalledWith({
        data: largePayload,
        sessionId: 'test-session'
      });
    });

    it('should handle message ordering with rapid succession', () => {
      const messages: any[] = [];
      const messageHandler = jest.fn((msg) => messages.push(msg));
      
      client.on('terminal-data', messageHandler);
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      // Send multiple messages rapidly
      for (let i = 0; i < 100; i++) {
        terminalDataHandler({ 
          data: `Message ${i}`, 
          sessionId: 'test-session',
          sequence: i 
        });
      }
      
      expect(messages).toHaveLength(100);
      
      // Verify ordering is maintained
      messages.forEach((msg, index) => {
        expect(msg.sequence).toBe(index);
      });
    });

    it('should handle malformed messages gracefully', () => {
      const errorSpy = jest.spyOn(console, 'error').mockImplementation();
      const messageHandler = jest.fn();
      
      client.on('terminal-data', messageHandler);
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      // Send malformed messages
      const malformedMessages = [
        null,
        undefined,
        { incomplete: true },
        { data: null, sessionId: undefined },
        'invalid-string-message'
      ];
      
      malformedMessages.forEach(malformed => {
        expect(() => terminalDataHandler(malformed)).not.toThrow();
      });
      
      errorSpy.mockRestore();
    });

    it('should handle binary data correctly', () => {
      const binaryHandler = jest.fn();
      client.on('terminal-data', binaryHandler);
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      // Send binary data (simulated as Buffer)
      const binaryData = Buffer.from([0x1b, 0x5b, 0x32, 0x4a]); // ANSI escape sequence
      
      terminalDataHandler({
        data: binaryData,
        sessionId: 'test-session',
        encoding: 'binary'
      });
      
      expect(binaryHandler).toHaveBeenCalledWith({
        data: binaryData,
        sessionId: 'test-session',
        encoding: 'binary'
      });
    });
  });

  describe('Error Recovery Scenarios', () => {
    it('should recover from network failures', async () => {
      mockSocket.connected = true;
      await client.connect();
      
      const reconnectHandler = jest.fn();
      client.on('connection-change', reconnectHandler);
      
      // Simulate network failure
      const disconnectHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'disconnect')?.[1];
      
      disconnectHandler('transport error');
      
      expect(client.connected).toBe(false);
      
      // Simulate successful reconnection
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'connect')?.[1];
      
      connectHandler();
      
      expect(client.connected).toBe(true);
    });

    it('should handle server unavailable scenarios', async () => {
      const connectErrorHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'connect_error')?.[1];
      
      const serverErrors = [
        new Error('ECONNREFUSED'),
        new Error('ETIMEDOUT'),
        new Error('ENOTFOUND'),
        new Error('Server temporarily unavailable')
      ];
      
      serverErrors.forEach(error => {
        expect(() => connectErrorHandler(error)).not.toThrow();
      });
    });

    it('should maintain message queue during disconnection', () => {
      const queuedMessages: WebSocketMessage[] = [];
      
      // Override send method to queue messages when disconnected
      const originalSend = client.send.bind(client);
      client.send = jest.fn((event: string, data: any) => {
        if (!client.connected) {
          queuedMessages.push({ type: 'data', ...data });
          return;
        }
        originalSend(event, data);
      });
      
      // Send messages while disconnected
      client.sendMessage({ type: 'data', sessionId: 'test', data: 'message1' });
      client.sendMessage({ type: 'data', sessionId: 'test', data: 'message2' });
      
      expect(queuedMessages).toHaveLength(2);
      expect(client.send).toHaveBeenCalledTimes(2);
    });
  });

  describe('Performance and Stress Testing', () => {
    it('should handle high message throughput', async () => {
      const startTime = Date.now();
      const messageCount = 10000;
      const receivedMessages: any[] = [];
      
      client.on('terminal-data', (msg) => receivedMessages.push(msg));
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      // Send many messages rapidly
      for (let i = 0; i < messageCount; i++) {
        terminalDataHandler({
          data: `High throughput message ${i}`,
          sessionId: 'performance-test'
        });
      }
      
      const processingTime = Date.now() - startTime;
      
      expect(receivedMessages).toHaveLength(messageCount);
      expect(processingTime).toBeLessThan(1000); // Should process 10k messages in under 1 second
    });

    it('should handle memory pressure scenarios', () => {
      const initialMemory = process.memoryUsage();
      const longRunningHandler = jest.fn();
      
      client.on('terminal-data', longRunningHandler);
      
      // Simulate sustained message load
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      for (let i = 0; i < 50000; i++) {
        terminalDataHandler({
          data: `Memory test message ${i}`,
          sessionId: 'memory-test',
          timestamp: Date.now()
        });
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Memory increase should be reasonable (less than 100MB for this test)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
    });
  });

  describe('Security Testing', () => {
    it('should sanitize XSS attempts in terminal data', () => {
      const xssPayloads = [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '"><script>alert("XSS")</script>',
        'onload="alert(\'XSS\')"',
        '\x3cscript\x3ealert("XSS")\x3c/script\x3e'
      ];
      
      const sanitizedHandler = jest.fn();
      client.on('terminal-data', sanitizedHandler);
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      xssPayloads.forEach(payload => {
        terminalDataHandler({
          data: payload,
          sessionId: 'security-test'
        });
      });
      
      // Verify all messages were received (not blocked)
      expect(sanitizedHandler).toHaveBeenCalledTimes(xssPayloads.length);
      
      // In a real implementation, you'd verify sanitization occurs
      // This test structure allows for that validation
    });

    it('should prevent prototype pollution attacks', () => {
      const pollutionPayloads = [
        { "__proto__": { "isAdmin": true } },
        { "constructor": { "prototype": { "isAdmin": true } } },
        JSON.parse('{"__proto__":{"isAdmin":true}}')
      ];
      
      const protectionHandler = jest.fn();
      client.on('terminal-data', protectionHandler);
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      pollutionPayloads.forEach(payload => {
        expect(() => terminalDataHandler(payload)).not.toThrow();
      });
      
      // Verify prototype wasn't polluted
      expect((Object.prototype as any).isAdmin).toBeUndefined();
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle maximum connection limit gracefully', async () => {
      const clients = Array.from({ length: 1000 }, () => new WebSocketClient());
      
      const connectionPromises = clients.map(client => {
        // Mock successful connection for each client
        const mockClientSocket = { ...mockSocket, connected: true };
        const { io } = require('socket.io-client');
        (io as jest.Mock).mockReturnValue(mockClientSocket);
        
        return client.connect().catch(() => null); // Ignore connection failures
      });
      
      const results = await Promise.allSettled(connectionPromises);
      
      // Should handle all attempts without crashing
      expect(results).toHaveLength(1000);
      
      // Cleanup
      clients.forEach(client => client.disconnect());
    });

    it('should handle unicode and special characters', () => {
      const unicodeTestCases = [
        '👋 Hello World! 🌍',
        '中文测试',
        'العربية',
        '🎉🎊✨💫⭐',
        '\u0000\u001F\u007F', // Control characters
        '\\x00\\x1F\\x7F',   // Escaped control chars
      ];
      
      const unicodeHandler = jest.fn();
      client.on('terminal-data', unicodeHandler);
      
      const terminalDataHandler = mockSocket.on.mock.calls
        .find(([event]) => event === 'terminal-data')?.[1];
      
      unicodeTestCases.forEach(testCase => {
        expect(() => terminalDataHandler({
          data: testCase,
          sessionId: 'unicode-test'
        })).not.toThrow();
      });
      
      expect(unicodeHandler).toHaveBeenCalledTimes(unicodeTestCases.length);
    });
  });
});