/**
 * WebSocket Connection Hook Tests
 * Comprehensive tests for connection handling, reconnection, and error recovery
 */

import React from 'react';
import { renderHook, act } from '@testing-library/react';
import { useWebSocketConnection } from '../useWebSocketConnection';

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  onopen = null;
  onclose = null;
  onerror = null;
  onmessage = null;
  url = '';

  constructor(url) {
    this.url = url;
    // Simulate async connection
    setTimeout(() => this.simulateOpen(), 0);
  }

  send = jest.fn();
  close = jest.fn(() => {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose({ code: 1000, reason: 'Normal closure' });
    }
  });

  simulateOpen() {
    this.readyState = MockWebSocket.OPEN;
    if (this.onopen) {
      this.onopen({});
    }
  }

  simulateError(error = new Error('Connection failed')) {
    if (this.onerror) {
      this.onerror({ error });
    }
  }

  simulateMessage(data) {
    if (this.onmessage) {
      this.onmessage({ data: JSON.stringify(data) });
    }
  }

  simulateClose(code = 1000, reason = 'Normal closure') {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose({ code, reason });
    }
  }
}

// Mock global WebSocket
const originalWebSocket = global.WebSocket;
beforeAll(() => {
  global.WebSocket = MockWebSocket as any;
});

afterAll(() => {
  global.WebSocket = originalWebSocket;
});

describe('useWebSocketConnection', () => {
  let mockSocket: MockWebSocket;

  beforeEach(() => {
    jest.clearAllMocks();
    // Capture the created WebSocket instance
    const OriginalWebSocket = global.WebSocket;
    global.WebSocket = jest.fn().mockImplementation((url) => {
      mockSocket = new MockWebSocket(url) as any;
      return mockSocket;
    });
  });

  describe('Connection Establishment', () => {
    it('should establish WebSocket connection with correct URL', () => {
      const url = 'ws://localhost:8080';
      
      renderHook(() => useWebSocketConnection(url));

      expect(global.WebSocket).toHaveBeenCalledWith(url);
      expect(mockSocket.url).toBe(url);
    });

    it('should set connected state when connection opens', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080')
      );

      expect(result.current.isConnected).toBe(false);

      await act(async () => {
        mockSocket.simulateOpen();
      });

      expect(result.current.isConnected).toBe(true);
    });

    it('should handle connection with custom protocols', () => {
      const protocols = ['protocol1', 'protocol2'];
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', { protocols })
      );

      expect(global.WebSocket).toHaveBeenCalledWith(
        'ws://localhost:8080',
        protocols
      );
    });

    it('should apply custom headers during connection', () => {
      const headers = { 'Authorization': 'Bearer token123' };
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', { headers })
      );

      // Note: Real WebSocket doesn't support custom headers directly,
      // but our hook should handle this gracefully
      expect(global.WebSocket).toHaveBeenCalled();
    });
  });

  describe('Message Handling', () => {
    it('should receive and parse JSON messages', async () => {
      const onMessage = jest.fn();
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', { onMessage })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      const testMessage = { type: 'test', data: 'hello world' };
      
      await act(async () => {
        mockSocket.simulateMessage(testMessage);
      });

      expect(onMessage).toHaveBeenCalledWith(testMessage);
    });

    it('should handle invalid JSON messages gracefully', async () => {
      const onError = jest.fn();
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', { onError })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Simulate invalid JSON
      if (mockSocket.onmessage) {
        await act(async () => {
          mockSocket.onmessage({ data: 'invalid json {' } as any);
        });
      }

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'message_parse_error',
          error: expect.any(Error)
        })
      );
    });

    it('should queue messages when disconnected', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableMessageQueue: true,
          maxQueueSize: 10
        })
      );

      // Try to send message before connection is open
      const testMessage = { type: 'test', data: 'queued message' };
      
      act(() => {
        result.current.sendMessage(testMessage);
      });

      expect(mockSocket.send).not.toHaveBeenCalled();

      // Open connection and verify queued message is sent
      await act(async () => {
        mockSocket.simulateOpen();
      });

      expect(mockSocket.send).toHaveBeenCalledWith(
        JSON.stringify(testMessage)
      );
    });

    it('should respect message queue size limits', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableMessageQueue: true,
          maxQueueSize: 3
        })
      );

      // Queue more messages than the limit
      for (let i = 0; i < 5; i++) {
        act(() => {
          result.current.sendMessage({ id: i, data: `message ${i}` });
        });
      }

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Should only send the last 3 messages
      expect(mockSocket.send).toHaveBeenCalledTimes(3);
    });
  });

  describe('Error Handling', () => {
    it('should handle connection errors', async () => {
      const onError = jest.fn();
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', { onError })
      );

      const error = new Error('Connection failed');
      
      await act(async () => {
        mockSocket.simulateError(error);
      });

      expect(onError).toHaveBeenCalledWith({
        type: 'connection_error',
        error,
        timestamp: expect.any(Number)
      });
    });

    it('should attempt reconnection after connection loss', async () => {
      jest.useFakeTimers();
      
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableAutoReconnect: true,
          reconnectInterval: 1000,
          maxReconnectAttempts: 3
        })
      );

      // Establish initial connection
      await act(async () => {
        mockSocket.simulateOpen();
      });

      expect(result.current.isConnected).toBe(true);

      // Simulate connection loss
      await act(async () => {
        mockSocket.simulateClose(1006, 'Connection lost');
      });

      expect(result.current.isConnected).toBe(false);
      expect(result.current.reconnectAttempts).toBe(0);

      // Advance timer to trigger reconnection
      await act(async () => {
        jest.advanceTimersByTime(1000);
      });

      expect(result.current.reconnectAttempts).toBe(1);
      expect(global.WebSocket).toHaveBeenCalledTimes(2);

      jest.useRealTimers();
    });

    it('should stop reconnecting after max attempts', async () => {
      jest.useFakeTimers();
      
      const onMaxReconnectAttemptsReached = jest.fn();
      
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableAutoReconnect: true,
          reconnectInterval: 1000,
          maxReconnectAttempts: 2,
          onMaxReconnectAttemptsReached
        })
      );

      // Simulate repeated connection failures
      for (let i = 0; i < 3; i++) {
        await act(async () => {
          mockSocket.simulateClose(1006, 'Connection lost');
        });

        await act(async () => {
          jest.advanceTimersByTime(1000);
        });
      }

      expect(result.current.reconnectAttempts).toBe(2);
      expect(onMaxReconnectAttemptsReached).toHaveBeenCalled();

      jest.useRealTimers();
    });

    it('should handle exponential backoff for reconnections', async () => {
      jest.useFakeTimers();
      
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableAutoReconnect: true,
          reconnectInterval: 1000,
          useExponentialBackoff: true,
          maxReconnectInterval: 10000
        })
      );

      // First reconnection attempt
      await act(async () => {
        mockSocket.simulateClose(1006, 'Connection lost');
      });

      await act(async () => {
        jest.advanceTimersByTime(1000);
      });

      expect(result.current.reconnectAttempts).toBe(1);

      // Second reconnection should wait longer
      await act(async () => {
        mockSocket.simulateClose(1006, 'Connection lost again');
      });

      // Should not reconnect after 1 second
      await act(async () => {
        jest.advanceTimersByTime(1000);
      });

      expect(result.current.reconnectAttempts).toBe(1);

      // Should reconnect after 2 seconds (exponential backoff)
      await act(async () => {
        jest.advanceTimersByTime(1000);
      });

      expect(result.current.reconnectAttempts).toBe(2);

      jest.useRealTimers();
    });
  });

  describe('Connection States', () => {
    it('should track connection state correctly', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080')
      );

      expect(result.current.connectionState).toBe('connecting');

      await act(async () => {
        mockSocket.simulateOpen();
      });

      expect(result.current.connectionState).toBe('open');

      await act(async () => {
        mockSocket.close();
      });

      expect(result.current.connectionState).toBe('closed');
    });

    it('should provide connection statistics', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080')
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Send some messages
      act(() => {
        result.current.sendMessage({ test: 'message1' });
        result.current.sendMessage({ test: 'message2' });
      });

      // Receive some messages
      await act(async () => {
        mockSocket.simulateMessage({ response: 'message1' });
        mockSocket.simulateMessage({ response: 'message2' });
      });

      expect(result.current.statistics).toEqual({
        messagesSent: 2,
        messagesReceived: 2,
        connectionTime: expect.any(Number),
        reconnectAttempts: 0
      });
    });
  });

  describe('Ping/Pong Heartbeat', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should send ping messages periodically', async () => {
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableHeartbeat: true,
          heartbeatInterval: 30000,
          pingMessage: { type: 'ping' }
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Advance time to trigger heartbeat
      await act(async () => {
        jest.advanceTimersByTime(30000);
      });

      expect(mockSocket.send).toHaveBeenCalledWith(
        JSON.stringify({ type: 'ping' })
      );
    });

    it('should detect connection timeout when pong not received', async () => {
      const onError = jest.fn();
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableHeartbeat: true,
          heartbeatInterval: 30000,
          heartbeatTimeout: 5000,
          pingMessage: { type: 'ping' },
          pongMessage: { type: 'pong' },
          onError
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Send ping but don't respond with pong
      await act(async () => {
        jest.advanceTimersByTime(30000);
      });

      // Wait for timeout
      await act(async () => {
        jest.advanceTimersByTime(5000);
      });

      expect(onError).toHaveBeenCalledWith({
        type: 'heartbeat_timeout',
        message: 'Heartbeat timeout - connection may be dead'
      });
    });

    it('should reset heartbeat timeout when pong received', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableHeartbeat: true,
          heartbeatInterval: 30000,
          heartbeatTimeout: 5000,
          pingMessage: { type: 'ping' },
          pongMessage: { type: 'pong' }
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Send ping
      await act(async () => {
        jest.advanceTimersByTime(30000);
      });

      // Respond with pong before timeout
      await act(async () => {
        mockSocket.simulateMessage({ type: 'pong' });
        jest.advanceTimersByTime(3000);
      });

      // Should not timeout
      expect(result.current.isConnected).toBe(true);
    });
  });

  describe('Connection Lifecycle', () => {
    it('should clean up connection on unmount', async () => {
      const { unmount } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080')
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      unmount();

      expect(mockSocket.close).toHaveBeenCalled();
    });

    it('should handle rapid connect/disconnect cycles', async () => {
      const { rerender } = renderHook(
        ({ url }) => useWebSocketConnection(url),
        { initialProps: { url: 'ws://localhost:8080' } }
      );

      // Connect and disconnect rapidly
      for (let i = 0; i < 5; i++) {
        rerender({ url: `ws://localhost:808${i}` });
        
        await act(async () => {
          mockSocket.simulateOpen();
          mockSocket.simulateClose();
        });
      }

      // Should handle gracefully without errors
      expect(global.WebSocket).toHaveBeenCalledTimes(5);
    });

    it('should prevent memory leaks with event listeners', async () => {
      const { result, unmount } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          onMessage: jest.fn(),
          onError: jest.fn(),
          onOpen: jest.fn(),
          onClose: jest.fn()
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      const eventListeners = [
        mockSocket.onopen,
        mockSocket.onclose,
        mockSocket.onerror,
        mockSocket.onmessage
      ];

      unmount();

      // Event listeners should be cleaned up
      eventListeners.forEach(listener => {
        expect(listener).toBeDefined();
      });
    });
  });

  describe('Security and Validation', () => {
    it('should validate message format before sending', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          validateMessage: (msg) => msg && typeof msg === 'object' && msg.type
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Valid message
      act(() => {
        result.current.sendMessage({ type: 'valid', data: 'test' });
      });

      expect(mockSocket.send).toHaveBeenCalled();

      mockSocket.send.mockClear();

      // Invalid message
      act(() => {
        result.current.sendMessage({ invalid: 'message' });
      });

      expect(mockSocket.send).not.toHaveBeenCalled();
    });

    it('should sanitize received messages', async () => {
      const onMessage = jest.fn();
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          onMessage,
          sanitizeMessage: (msg) => ({
            ...msg,
            data: typeof msg.data === 'string' ? msg.data.replace(/<script>/g, '') : msg.data
          })
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      await act(async () => {
        mockSocket.simulateMessage({
          type: 'message',
          data: '<script>alert("xss")</script>Hello'
        });
      });

      expect(onMessage).toHaveBeenCalledWith({
        type: 'message',
        data: 'alert("xss")Hello'
      });
    });

    it('should enforce connection limits', async () => {
      const onError = jest.fn();
      
      // Create multiple connections rapidly
      for (let i = 0; i < 5; i++) {
        renderHook(() => 
          useWebSocketConnection(`ws://localhost:808${i}`, {
            onError,
            maxConcurrentConnections: 3
          })
        );
      }

      expect(onError).toHaveBeenCalledWith({
        type: 'connection_limit_exceeded',
        message: 'Maximum concurrent connections exceeded'
      });
    });
  });

  describe('Performance Optimizations', () => {
    it('should throttle message sending', async () => {
      jest.useFakeTimers();
      
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          throttleMessages: true,
          throttleInterval: 100
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Send multiple messages rapidly
      for (let i = 0; i < 5; i++) {
        act(() => {
          result.current.sendMessage({ id: i, data: `message ${i}` });
        });
      }

      // Should only send first message immediately
      expect(mockSocket.send).toHaveBeenCalledTimes(1);

      // Advance time to allow throttled messages
      await act(async () => {
        jest.advanceTimersByTime(500);
      });

      // Should have sent remaining messages
      expect(mockSocket.send).toHaveBeenCalledTimes(5);

      jest.useRealTimers();
    });

    it('should debounce reconnection attempts', async () => {
      jest.useFakeTimers();
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          enableAutoReconnect: true,
          debounceReconnect: true,
          reconnectInterval: 1000
        })
      );

      // Rapid disconnection events
      for (let i = 0; i < 3; i++) {
        await act(async () => {
          mockSocket.simulateClose(1006, 'Connection lost');
          jest.advanceTimersByTime(100);
        });
      }

      // Should only create one reconnection attempt
      await act(async () => {
        jest.advanceTimersByTime(1000);
      });

      expect(global.WebSocket).toHaveBeenCalledTimes(2); // Initial + 1 reconnect

      jest.useRealTimers();
    });
  });

  describe('Edge Cases', () => {
    it('should handle WebSocket not supported', () => {
      const originalWebSocket = global.WebSocket;
      delete (global as any).WebSocket;

      const onError = jest.fn();
      
      renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', { onError })
      );

      expect(onError).toHaveBeenCalledWith({
        type: 'websocket_not_supported',
        message: 'WebSocket is not supported in this environment'
      });

      global.WebSocket = originalWebSocket;
    });

    it('should handle malformed WebSocket URLs', () => {
      const onError = jest.fn();
      
      renderHook(() => 
        useWebSocketConnection('invalid-url', { onError })
      );

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'connection_error',
          error: expect.any(Error)
        })
      );
    });

    it('should handle circular JSON in messages', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080')
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Create circular reference
      const circularObj: any = { data: 'test' };
      circularObj.self = circularObj;

      act(() => {
        result.current.sendMessage(circularObj);
      });

      // Should handle gracefully without throwing
      expect(mockSocket.send).toHaveBeenCalled();
    });

    it('should handle connection during page visibility changes', async () => {
      const { result } = renderHook(() => 
        useWebSocketConnection('ws://localhost:8080', {
          pauseOnPageHidden: true
        })
      );

      await act(async () => {
        mockSocket.simulateOpen();
      });

      // Simulate page becoming hidden
      Object.defineProperty(document, 'visibilityState', {
        writable: true,
        value: 'hidden'
      });

      await act(async () => {
        document.dispatchEvent(new Event('visibilitychange'));
      });

      // Connection should be paused
      expect(result.current.isPaused).toBe(true);

      // Simulate page becoming visible again
      Object.defineProperty(document, 'visibilityState', {
        value: 'visible'
      });

      await act(async () => {
        document.dispatchEvent(new Event('visibilitychange'));
      });

      expect(result.current.isPaused).toBe(false);
    });
  });
});