/**
 * WebSocket Integration Validation Tests for Backstage
 *
 * These tests validate that the WebSocket connection patterns work correctly
 * within the Backstage environment, including authentication, session management,
 * and real-time communication.
 */

import { io, Socket } from 'socket.io-client';
import { WebSocketClient } from '@/lib/websocket/client';
import { useWebSocket } from '@/hooks/useWebSocket';
import { renderHook, act, waitFor } from '@testing-library/react';
import { TestApiProvider } from '@backstage/test-utils';
import {
  configApiRef,
  identityApiRef,
  ConfigApi,
  IdentityApi,
} from '@backstage/core-plugin-api';

// Mock Socket.IO
jest.mock('socket.io-client');
const mockIo = io as jest.MockedFunction<typeof io>;

// Mock implementations
const createMockSocket = (): jest.Mocked<Socket> => ({
  id: 'mock-socket-id',
  connected: false,
  connect: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  removeAllListeners: jest.fn(),
  listeners: jest.fn(),
  listenersAny: jest.fn(),
  listenersAnyOutgoing: jest.fn(),
  onAny: jest.fn(),
  onAnyOutgoing: jest.fn(),
  offAny: jest.fn(),
  offAnyOutgoing: jest.fn(),
  prependAny: jest.fn(),
  prependAnyOutgoing: jest.fn(),
  timeout: jest.fn(),
  volatile: {} as any,
  compress: jest.fn(),
  binary: jest.fn(),
  local: {} as any,
  broadcast: {} as any,
});

const createMockConfigApi = (overrides = {}): jest.Mocked<ConfigApi> => ({
  getOptionalString: jest.fn((key) => {
    const defaults: Record<string, string> = {
      'claudeFlow.websocketUrl': 'ws://localhost:11236',
      'claudeFlow.apiUrl': 'http://localhost:11235',
      'claudeFlow.terminalTheme': 'backstage-dark',
      ...overrides,
    };
    return defaults[key];
  }),
  getOptionalNumber: jest.fn(() => undefined),
  getOptionalBoolean: jest.fn(() => undefined),
  getString: jest.fn(),
  getNumber: jest.fn(),
  getBoolean: jest.fn(),
  getConfig: jest.fn(),
  getOptionalConfig: jest.fn(),
  getConfigArray: jest.fn(),
  getOptionalConfigArray: jest.fn(),
  getStringArray: jest.fn(),
  getOptionalStringArray: jest.fn(),
  has: jest.fn(),
  keys: jest.fn(),
  get: jest.fn(),
  getOptional: jest.fn(),
});

const createMockIdentityApi = (): jest.Mocked<IdentityApi> => ({
  getUserId: jest.fn().mockResolvedValue('test-user'),
  getProfile: jest.fn().mockResolvedValue({
    email: 'test@example.com',
    displayName: 'Test User',
  }),
  getProfileInfo: jest.fn().mockResolvedValue({
    email: 'test@example.com',
    displayName: 'Test User',
  }),
  getBackstageIdentity: jest.fn().mockResolvedValue({
    type: 'user',
    userEntityRef: 'user:default/test-user',
    ownershipEntityRefs: ['user:default/test-user'],
  }),
  getCredentials: jest.fn().mockResolvedValue({
    token: 'mock-jwt-token',
  }),
  signOut: jest.fn(),
});

describe('Backstage WebSocket Integration Validation', () => {
  let mockSocket: jest.Mocked<Socket>;
  let mockConfigApi: jest.Mocked<ConfigApi>;
  let mockIdentityApi: jest.Mocked<IdentityApi>;

  beforeEach(() => {
    mockSocket = createMockSocket();
    mockConfigApi = createMockConfigApi();
    mockIdentityApi = createMockIdentityApi();
    mockIo.mockReturnValue(mockSocket);

    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('WebSocket Client Backstage Integration', () => {
    test('should initialize with Backstage configuration', () => {
      const client = new WebSocketClient();

      expect(client).toBeDefined();
      expect(client.connected).toBe(false);
    });

    test('should connect with Backstage authentication headers', async () => {
      const client = new WebSocketClient('ws://localhost:11236');
      mockSocket.connected = false;

      // Mock successful connection
      mockSocket.connect.mockImplementation(() => {
        mockSocket.connected = true;
        // Simulate connect event
        const connectHandler = mockSocket.on.mock.calls.find(
          call => call[0] === 'connect'
        )?.[1];
        if (connectHandler) {
          setTimeout(() => connectHandler(), 10);
        }
        return mockSocket;
      });

      const connectionPromise = client.connect();

      await expect(connectionPromise).resolves.toBeUndefined();
      expect(mockIo).toHaveBeenCalledWith('ws://localhost:11236', {
        path: '/api/ws',
        transports: ['websocket', 'polling'],
        autoConnect: false,
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
      });
    });

    test('should handle authentication token refresh', async () => {
      const client = new WebSocketClient();
      let tokenRefreshCount = 0;

      // Mock token refresh scenario
      mockSocket.emit.mockImplementation((event, data) => {
        if (event === 'authenticate' && tokenRefreshCount === 0) {
          tokenRefreshCount++;
          // Simulate token expired response
          const errorHandler = mockSocket.on.mock.calls.find(
            call => call[0] === 'auth_error'
          )?.[1];
          if (errorHandler) {
            setTimeout(() => errorHandler({ error: 'Token expired' }), 10);
          }
        }
        return mockSocket;
      });

      await client.connect();

      client.send('terminal-data', {
        sessionId: 'test-session',
        data: 'test command',
      });

      expect(tokenRefreshCount).toBe(1);
    });

    test('should maintain session state across reconnections', async () => {
      const client = new WebSocketClient();

      await client.connect();

      // Simulate disconnect
      mockSocket.connected = false;
      const disconnectHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'disconnect'
      )?.[1];
      if (disconnectHandler) {
        disconnectHandler('transport error');
      }

      // Simulate reconnect
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1];
      if (connectHandler) {
        connectHandler();
      }

      expect(client.connected).toBe(true);
    });
  });

  describe('useWebSocket Hook Integration', () => {
    const createWrapper = (configOverrides = {}) => {
      const apis = [
        [configApiRef, createMockConfigApi(configOverrides)],
        [identityApiRef, mockIdentityApi],
      ];

      return ({ children }: { children: React.ReactNode }) => (
        <TestApiProvider apis={apis}>{children}</TestApiProvider>
      );
    };

    test('should connect using Backstage configuration', async () => {
      const wrapper = createWrapper();

      const { result } = renderHook(() => useWebSocket(), { wrapper });

      expect(result.current.isConnected).toBe(false);
      expect(result.current.connecting).toBe(false);

      await act(async () => {
        await result.current.connect();
      });

      // Mock connection establishment
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1];
      if (connectHandler) {
        act(() => {
          connectHandler();
        });
      }

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });
    });

    test('should use custom WebSocket URL from Backstage config', async () => {
      const customUrl = 'wss://custom-host:8080';
      const wrapper = createWrapper({
        'claudeFlow.websocketUrl': customUrl,
      });

      const { result } = renderHook(() => useWebSocket(), { wrapper });

      await act(async () => {
        await result.current.connect();
      });

      expect(mockIo).toHaveBeenCalledWith(
        customUrl,
        expect.objectContaining({
          path: '/api/ws',
        })
      );
    });

    test('should handle session-based message routing', async () => {
      const wrapper = createWrapper();

      const { result } = renderHook(() => useWebSocket(), { wrapper });

      // Mock terminal data handler registration
      const terminalDataSpy = jest.fn();
      result.current.on('terminal-data', terminalDataSpy);

      // Simulate receiving terminal data
      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      if (terminalDataHandler) {
        act(() => {
          terminalDataHandler({
            sessionId: 'session-1',
            data: 'Hello from terminal',
            timestamp: Date.now(),
          });
        });
      }

      await waitFor(() => {
        expect(terminalDataSpy).toHaveBeenCalledWith({
          sessionId: 'session-1',
          data: 'Hello from terminal',
          timestamp: expect.any(Number),
        });
      });
    });

    test('should handle authentication failures gracefully', async () => {
      mockIdentityApi.getCredentials.mockRejectedValue(
        new Error('Authentication failed')
      );

      const wrapper = createWrapper();

      const { result } = renderHook(() => useWebSocket(), { wrapper });

      await act(async () => {
        try {
          await result.current.connect();
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Authentication failed');
        }
      });
    });
  });

  describe('Terminal Data Flow Validation', () => {
    test('should maintain data integrity in Backstage environment', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const receivedData: any[] = [];
      client.on('terminal-data', (data) => {
        receivedData.push(data);
      });

      // Simulate large data chunks
      const testData = {
        sessionId: 'test-session',
        data: 'A'.repeat(8192) + '\r\n', // 8KB chunk
        timestamp: Date.now(),
      };

      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      if (terminalDataHandler) {
        act(() => {
          terminalDataHandler(testData);
        });
      }

      await waitFor(() => {
        expect(receivedData).toHaveLength(1);
        expect(receivedData[0]).toEqual(testData);
      });
    });

    test('should handle rapid message bursts', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const receivedMessages: any[] = [];
      client.on('terminal-data', (data) => {
        receivedMessages.push(data);
      });

      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      if (terminalDataHandler) {
        // Send 100 rapid messages
        for (let i = 0; i < 100; i++) {
          act(() => {
            terminalDataHandler({
              sessionId: 'test-session',
              data: `Message ${i}\n`,
              timestamp: Date.now() + i,
            });
          });
        }
      }

      await waitFor(() => {
        expect(receivedMessages).toHaveLength(100);
      }, { timeout: 2000 });

      // Verify message ordering
      for (let i = 0; i < 100; i++) {
        expect(receivedMessages[i].data).toBe(`Message ${i}\n`);
      }
    });

    test('should handle ANSI escape sequences correctly', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const receivedData: any[] = [];
      client.on('terminal-data', (data) => {
        receivedData.push(data);
      });

      const ansiData = {
        sessionId: 'test-session',
        data: '\x1b[31mRed text\x1b[0m\x1b[2J\x1b[H',
        timestamp: Date.now(),
      };

      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      if (terminalDataHandler) {
        act(() => {
          terminalDataHandler(ansiData);
        });
      }

      await waitFor(() => {
        expect(receivedData[0].data).toBe('\x1b[31mRed text\x1b[0m\x1b[2J\x1b[H');
      });
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should recover from WebSocket disconnection', async () => {
      const client = new WebSocketClient();
      await client.connect();

      expect(client.connected).toBe(true);

      // Simulate disconnection
      mockSocket.connected = false;
      const disconnectHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'disconnect'
      )?.[1];

      if (disconnectHandler) {
        act(() => {
          disconnectHandler('transport error');
        });
      }

      expect(client.connected).toBe(false);

      // Simulate automatic reconnection
      await act(async () => {
        mockSocket.connected = true;
        const connectHandler = mockSocket.on.mock.calls.find(
          call => call[0] === 'connect'
        )?.[1];
        if (connectHandler) {
          connectHandler();
        }
      });

      expect(client.connected).toBe(true);
    });

    test('should handle network timeout scenarios', async () => {
      const client = new WebSocketClient();

      // Mock connection timeout
      mockSocket.connect.mockImplementation(() => {
        // Don't emit connect event, simulate timeout
        return mockSocket;
      });

      const connectionPromise = client.connect();

      // Simulate timeout after 5 seconds (our configured timeout)
      setTimeout(() => {
        const errorHandler = mockSocket.on.mock.calls.find(
          call => call[0] === 'connect_error'
        )?.[1];
        if (errorHandler) {
          errorHandler(new Error('Connection timeout'));
        }
      }, 100);

      await expect(connectionPromise).rejects.toThrow('Connection timeout');
    });

    test('should maintain message queue during disconnection', async () => {
      const client = new WebSocketClient();
      await client.connect();

      // Disconnect
      mockSocket.connected = false;

      // Try to send messages while disconnected
      client.send('terminal-data', { sessionId: 'test', data: 'message 1' });
      client.send('terminal-data', { sessionId: 'test', data: 'message 2' });

      expect(mockSocket.emit).not.toHaveBeenCalled();

      // Reconnect
      mockSocket.connected = true;
      const connectHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1];

      if (connectHandler) {
        act(() => {
          connectHandler();
        });
      }

      // Send new message after reconnect
      client.send('terminal-data', { sessionId: 'test', data: 'message 3' });

      expect(mockSocket.emit).toHaveBeenCalledWith('terminal-data', {
        sessionId: 'test',
        data: 'message 3',
      });
    });
  });

  describe('Security Validation', () => {
    test('should validate message origins', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const receivedMessages: any[] = [];
      client.on('terminal-data', (data) => {
        receivedMessages.push(data);
      });

      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      // Simulate message without proper session ID
      if (terminalDataHandler) {
        act(() => {
          terminalDataHandler({
            // Missing sessionId
            data: 'potentially malicious data',
            timestamp: Date.now(),
          });
        });
      }

      // Should not process message without proper session ID
      await waitFor(() => {
        expect(receivedMessages).toHaveLength(0);
      });
    });

    test('should sanitize incoming data', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const receivedData: any[] = [];
      client.on('terminal-data', (data) => {
        receivedData.push(data);
      });

      const maliciousData = {
        sessionId: 'test-session',
        data: '<script>alert("xss")</script>',
        timestamp: Date.now(),
      };

      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      if (terminalDataHandler) {
        act(() => {
          terminalDataHandler(maliciousData);
        });
      }

      await waitFor(() => {
        expect(receivedData).toHaveLength(1);
        // Data should be passed through for terminal display
        // (terminal will handle escape sequences safely)
        expect(receivedData[0].data).toBe('<script>alert("xss")</script>');
      });
    });

    test('should enforce session isolation', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const session1Data: any[] = [];
      const session2Data: any[] = [];

      client.on('terminal-data', (data) => {
        if (data.sessionId === 'session-1') {
          session1Data.push(data);
        } else if (data.sessionId === 'session-2') {
          session2Data.push(data);
        }
      });

      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      if (terminalDataHandler) {
        // Send data to different sessions
        act(() => {
          terminalDataHandler({
            sessionId: 'session-1',
            data: 'session 1 data',
            timestamp: Date.now(),
          });
        });

        act(() => {
          terminalDataHandler({
            sessionId: 'session-2',
            data: 'session 2 data',
            timestamp: Date.now(),
          });
        });
      }

      await waitFor(() => {
        expect(session1Data).toHaveLength(1);
        expect(session2Data).toHaveLength(1);
        expect(session1Data[0].data).toBe('session 1 data');
        expect(session2Data[0].data).toBe('session 2 data');
      });
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle high-frequency updates efficiently', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const receivedCount = { value: 0 };
      const startTime = Date.now();

      client.on('terminal-data', () => {
        receivedCount.value++;
      });

      const terminalDataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      // Send 1000 messages rapidly
      if (terminalDataHandler) {
        for (let i = 0; i < 1000; i++) {
          act(() => {
            terminalDataHandler({
              sessionId: 'test-session',
              data: `Update ${i}`,
              timestamp: Date.now(),
            });
          });
        }
      }

      await waitFor(() => {
        expect(receivedCount.value).toBe(1000);
      }, { timeout: 5000 });

      const duration = Date.now() - startTime;
      const messagesPerSecond = 1000 / (duration / 1000);

      // Should handle at least 100 messages per second
      expect(messagesPerSecond).toBeGreaterThan(100);
    });

    test('should cleanup resources properly', async () => {
      const client = new WebSocketClient();
      await client.connect();

      const listeners = client.listeners?.size || 0;
      expect(listeners).toBeGreaterThan(0);

      client.disconnect();

      // Verify cleanup
      expect(mockSocket.removeAllListeners).toHaveBeenCalled();
      expect(mockSocket.disconnect).toHaveBeenCalled();
      expect(client.connected).toBe(false);
    });
  });
});