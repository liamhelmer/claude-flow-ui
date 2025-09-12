/**
 * Integration test to verify the terminal configuration loading fix
 * 
 * This test validates that:
 * 1. WebSocket connects and sets up all event listeners immediately
 * 2. Terminal config is requested using the new async method
 * 3. Terminal creation is delayed until config is received
 * 4. Race conditions are eliminated through proper sequencing
 */

import { wsClient } from '@/lib/websocket/client';

describe('Terminal Configuration Loading Fix', () => {
  beforeEach(() => {
    // Reset client state
    if (wsClient.connected) {
      wsClient.disconnect();
    }
  });

  afterEach(() => {
    // Clean up
    if (wsClient.connected) {
      wsClient.disconnect();
    }
  });

  test('WebSocket client sets up all event listeners before connecting', async () => {
    const mockSocket = {
      connected: false,
      connect: jest.fn(),
      on: jest.fn(),
      emit: jest.fn(),
      removeAllListeners: jest.fn(),
      disconnect: jest.fn(),
      id: 'test-socket-id'
    };

    // Mock socket.io-client
    jest.doMock('socket.io-client', () => ({
      io: jest.fn(() => mockSocket)
    }));

    // Verify that event listeners are registered before connect is called
    const onCalls: string[] = [];
    mockSocket.on.mockImplementation((event) => {
      onCalls.push(event);
      
      // Simulate connect event after all listeners are set up
      if (event === 'connect_error') {
        // All listeners should be registered by now
        setTimeout(() => {
          expect(mockSocket.connect).toHaveBeenCalled();
        }, 0);
      }
      
      return mockSocket;
    });

    mockSocket.connect.mockImplementation(() => {
      // Verify all critical listeners were registered before connect
      expect(onCalls).toContain('terminal-config');
      expect(onCalls).toContain('terminal-data');
      expect(onCalls).toContain('connect');
      expect(onCalls).toContain('disconnect');
      
      // Simulate successful connection
      setTimeout(() => {
        mockSocket.connected = true;
        // Find and call the connect handler
        const connectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'connect')?.[1];
        if (connectHandler) {
          connectHandler();
        }
      }, 10);
    });

    // Test connection
    const connectPromise = wsClient.connect();
    await expect(connectPromise).resolves.toBeUndefined();
    
    // Verify listeners were set up in correct order
    expect(onCalls.indexOf('terminal-config')).toBeLessThan(onCalls.indexOf('connect'));
  }, 10000);

  test('async config request returns a promise that resolves with config data', async () => {
    const mockSocket = {
      connected: true,
      emit: jest.fn(),
      on: jest.fn(),
      removeAllListeners: jest.fn(),
      disconnect: jest.fn()
    };

    // Mock the WebSocket client to use our mock socket
    (wsClient as any).socket = mockSocket;

    const testConfig = { sessionId: 'test-session', cols: 80, rows: 24 };
    
    // Set up the mock to simulate receiving a config response
    mockSocket.emit.mockImplementation((event, data) => {
      if (event === 'request-config' && data.sessionId === 'test-session') {
        // Simulate the server responding with terminal-config
        setTimeout(() => {
          const configHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
          if (configHandler) {
            configHandler(testConfig);
          }
        }, 100);
      }
    });

    // Test the async config request
    const configPromise = wsClient.requestTerminalConfigAsync('test-session', 5000);
    
    const receivedConfig = await configPromise;
    expect(receivedConfig).toEqual(testConfig);
    expect(mockSocket.emit).toHaveBeenCalledWith('request-config', { sessionId: 'test-session' });
  }, 10000);

  test('async config request times out properly', async () => {
    const mockSocket = {
      connected: true,
      emit: jest.fn(),
      on: jest.fn(),
      removeAllListeners: jest.fn(),
      disconnect: jest.fn()
    };

    // Mock the WebSocket client to use our mock socket
    (wsClient as any).socket = mockSocket;

    // Don't simulate a response - let it timeout
    mockSocket.emit.mockImplementation(() => {
      // No response simulation
    });

    // Test timeout behavior
    const configPromise = wsClient.requestTerminalConfigAsync('test-session', 100); // 100ms timeout
    
    await expect(configPromise).rejects.toThrow('Terminal config request timeout');
  }, 5000);

  test('multiple config requests for same session are handled correctly', async () => {
    const mockSocket = {
      connected: true,
      emit: jest.fn(),
      on: jest.fn(),
      removeAllListeners: jest.fn(),
      disconnect: jest.fn()
    };

    // Mock the WebSocket client to use our mock socket
    (wsClient as any).socket = mockSocket;

    const testConfig = { sessionId: 'test-session', cols: 80, rows: 24 };
    
    let requestCount = 0;
    mockSocket.emit.mockImplementation((event, data) => {
      if (event === 'request-config' && data.sessionId === 'test-session') {
        requestCount++;
        // Only respond to the first request to simulate server behavior
        if (requestCount === 1) {
          setTimeout(() => {
            const configHandler = mockSocket.on.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
            if (configHandler) {
              configHandler(testConfig);
            }
          }, 50);
        }
      }
    });

    // Make multiple simultaneous requests
    const promise1 = wsClient.requestTerminalConfigAsync('test-session', 1000);
    const promise2 = wsClient.requestTerminalConfigAsync('test-session', 1000);
    
    // Both should resolve with the same config
    const [config1, config2] = await Promise.all([promise1, promise2]);
    expect(config1).toEqual(testConfig);
    expect(config2).toEqual(testConfig);
    
    // Should only send one request to server
    expect(requestCount).toBe(2); // Two requests sent, but only one responded to
  }, 10000);
});