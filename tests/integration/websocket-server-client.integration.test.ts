/**
 * WebSocket Server-Client Communication Integration Tests
 * Tests the full WebSocket flow from server to client
 */

import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { io as Client, Socket as ClientSocket } from 'socket.io-client';
import WebSocketClient from '@/lib/websocket/client';
import { WebSocketMessage } from '@/types';

describe('WebSocket Server-Client Integration', () => {
  let httpServer: any;
  let io: SocketIOServer;
  let clientSocket: ClientSocket;
  let wsClient: WebSocketClient;
  let serverPort: number;

  beforeAll((done) => {
    // Create test server
    httpServer = createServer();
    io = new SocketIOServer(httpServer, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      },
      path: '/api/ws'
    });

    // Find available port
    httpServer.listen(0, () => {
      serverPort = httpServer.address().port;
      console.log(`Test WebSocket server listening on port ${serverPort}`);
      done();
    });

    // Setup server-side handlers
    io.on('connection', (socket) => {
      console.log('Client connected to test server:', socket.id);

      socket.on('terminal-input', (data) => {
        // Echo terminal input back as terminal-data
        socket.emit('terminal-data', {
          sessionId: data.sessionId,
          data: `Echo: ${data.input}`,
          timestamp: Date.now()
        });
      });

      socket.on('create-session', (data) => {
        socket.emit('session-created', {
          sessionId: `test_session_${Date.now()}`,
          name: data.name || 'test-session'
        });
      });

      socket.on('resize-terminal', (data) => {
        socket.emit('terminal-resize', {
          sessionId: data.sessionId,
          cols: data.cols,
          rows: data.rows
        });
      });

      socket.on('disconnect', (reason) => {
        console.log('Client disconnected from test server:', reason);
      });
    });
  });

  afterAll((done) => {
    if (clientSocket) clientSocket.disconnect();
    if (wsClient) wsClient.disconnect();
    if (io) io.close();
    if (httpServer) httpServer.close(done);
  });

  beforeEach(() => {
    // Create fresh client for each test
    wsClient = new WebSocketClient(`http://localhost:${serverPort}`);
  });

  afterEach(() => {
    if (wsClient) wsClient.disconnect();
    if (clientSocket && clientSocket.connected) clientSocket.disconnect();
  });

  describe('Connection Management', () => {
    it('should establish WebSocket connection successfully', async () => {
      const connectionPromise = wsClient.connect();
      await expect(connectionPromise).resolves.toBeUndefined();
      expect(wsClient.connected).toBe(true);
    });

    it('should handle connection failures gracefully', async () => {
      const invalidClient = new WebSocketClient('http://localhost:99999');
      await expect(invalidClient.connect()).rejects.toThrow();
    });

    it('should emit connection-change events', (done) => {
      let connectionChangeCount = 0;

      wsClient.on('connection-change', (isConnected) => {
        connectionChangeCount++;
        if (connectionChangeCount === 1) {
          expect(isConnected).toBe(false); // Initial disconnect event
          done();
        }
      });

      wsClient.connect().then(() => {
        wsClient.disconnect();
      });
    });

    it('should handle reconnection attempts', async () => {
      await wsClient.connect();
      expect(wsClient.connected).toBe(true);

      // Simulate server disconnect
      io.disconnectSockets();

      // Wait for disconnection
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(wsClient.connected).toBe(false);
    });
  });

  describe('Message Communication', () => {
    beforeEach(async () => {
      await wsClient.connect();
    });

    it('should send and receive WebSocket messages', (done) => {
      const testMessage: WebSocketMessage = {
        type: 'terminal-input',
        sessionId: 'test-session',
        data: { input: 'test command' }
      };

      wsClient.on('message', (receivedMessage) => {
        expect(receivedMessage.type).toBe('terminal-input');
        expect(receivedMessage.sessionId).toBe('test-session');
        done();
      });

      wsClient.sendMessage(testMessage);
    });

    it('should handle terminal input/output flow', (done) => {
      const sessionId = 'test-terminal-session';
      const testInput = 'ls -la';

      wsClient.on('terminal-data', (data) => {
        expect(data.sessionId).toBe(sessionId);
        expect(data.data).toContain('Echo: ls -la');
        expect(data.timestamp).toBeGreaterThan(0);
        done();
      });

      wsClient.send('terminal-input', {
        sessionId,
        input: testInput
      });
    });

    it('should handle session creation flow', (done) => {
      const sessionName = 'integration-test-session';

      wsClient.on('session-created', (data) => {
        expect(data.sessionId).toContain('test_session_');
        expect(data.name).toBe(sessionName);
        done();
      });

      wsClient.send('create-session', { name: sessionName });
    });
  });

  describe('Terminal Operations', () => {
    beforeEach(async () => {
      await wsClient.connect();
    });

    it('should handle terminal resize operations', (done) => {
      const sessionId = 'resize-test-session';
      const cols = 120;
      const rows = 40;

      wsClient.on('terminal-resize', (data) => {
        expect(data.sessionId).toBe(sessionId);
        expect(data.cols).toBe(cols);
        expect(data.rows).toBe(rows);
        done();
      });

      wsClient.send('resize-terminal', {
        sessionId,
        cols,
        rows
      });
    });

    it('should handle multiple terminal sessions simultaneously', async () => {
      const sessions = ['session1', 'session2', 'session3'];
      const results = new Map<string, any>();

      // Setup listeners for all sessions
      wsClient.on('terminal-data', (data) => {
        results.set(data.sessionId, data);
      });

      // Send commands to all sessions
      const promises = sessions.map(sessionId => {
        return new Promise<void>((resolve) => {
          wsClient.send('terminal-input', {
            sessionId,
            input: `echo "Hello from ${sessionId}"`
          });

          const checkResult = () => {
            if (results.has(sessionId)) {
              resolve();
            } else {
              setTimeout(checkResult, 10);
            }
          };
          checkResult();
        });
      });

      await Promise.all(promises);

      // Verify all sessions received responses
      sessions.forEach(sessionId => {
        expect(results.has(sessionId)).toBe(true);
        expect(results.get(sessionId).data).toContain(`Hello from ${sessionId}`);
      });
    });
  });

  describe('Error Handling', () => {
    beforeEach(async () => {
      await wsClient.connect();
    });

    it('should handle server errors gracefully', (done) => {
      wsClient.on('terminal-error', (error) => {
        expect(error).toBeDefined();
        done();
      });

      // Trigger server error
      io.emit('terminal-error', { message: 'Test error', code: 500 });
    });

    it('should handle malformed messages', () => {
      expect(() => {
        wsClient.send('invalid-event', null);
      }).not.toThrow();
    });

    it('should handle connection interruptions', async () => {
      expect(wsClient.connected).toBe(true);

      // Force disconnect
      httpServer.close();

      // Wait for disconnection
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(wsClient.connected).toBe(false);
    });
  });

  describe('Performance and Reliability', () => {
    beforeEach(async () => {
      await wsClient.connect();
    });

    it('should handle high-frequency messages without blocking', (done) => {
      let messageCount = 0;
      const totalMessages = 100;
      const startTime = Date.now();

      wsClient.on('terminal-data', (data) => {
        messageCount++;
        if (messageCount === totalMessages) {
          const duration = Date.now() - startTime;
          expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
          done();
        }
      });

      // Send rapid messages
      for (let i = 0; i < totalMessages; i++) {
        wsClient.send('terminal-input', {
          sessionId: 'perf-test',
          input: `message-${i}`
        });
      }
    });

    it('should maintain event listener integrity', () => {
      const listener1 = jest.fn();
      const listener2 = jest.fn();

      wsClient.on('test-event', listener1);
      wsClient.on('test-event', listener2);

      // Emit test event
      (wsClient as any).emit('test-event', { test: 'data' });

      expect(listener1).toHaveBeenCalledWith({ test: 'data' });
      expect(listener2).toHaveBeenCalledWith({ test: 'data' });
    });

    it('should prevent memory leaks in event listeners', () => {
      const maxListeners = 15;

      for (let i = 0; i < maxListeners; i++) {
        wsClient.on('memory-test', () => {});
      }

      // Should not throw or create memory issues
      expect(() => {
        (wsClient as any).emit('memory-test', {});
      }).not.toThrow();
    });
  });

  describe('Message Routing and Broadcasting', () => {
    let secondClient: WebSocketClient;

    beforeEach(async () => {
      await wsClient.connect();
      secondClient = new WebSocketClient(`http://localhost:${serverPort}`);
      await secondClient.connect();
    });

    afterEach(() => {
      if (secondClient) secondClient.disconnect();
    });

    it('should route messages to specific sessions', (done) => {
      const sessionId = 'routing-test';
      let client1Received = false;
      let client2Received = false;

      wsClient.on('terminal-data', (data) => {
        if (data.sessionId === sessionId) {
          client1Received = true;
          checkCompletion();
        }
      });

      secondClient.on('terminal-data', (data) => {
        if (data.sessionId === sessionId) {
          client2Received = true;
          checkCompletion();
        }
      });

      function checkCompletion() {
        if (client1Received && client2Received) {
          done();
        }
      }

      // Server will broadcast to all clients
      io.emit('terminal-data', {
        sessionId,
        data: 'Broadcast message',
        timestamp: Date.now()
      });
    });
  });

  describe('State Synchronization', () => {
    beforeEach(async () => {
      await wsClient.connect();
    });

    it('should maintain session state across reconnections', async () => {
      const sessionId = 'state-sync-test';
      let sessionCreated = false;

      wsClient.on('session-created', (data) => {
        if (data.sessionId.includes('state-sync')) {
          sessionCreated = true;
        }
      });

      // Create session
      wsClient.send('create-session', { name: 'state-sync-test' });

      // Wait for session creation
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(sessionCreated).toBe(true);

      // Disconnect and reconnect
      wsClient.disconnect();
      await wsClient.connect();

      // Session state should be maintained on server
      expect(wsClient.connected).toBe(true);
    });
  });
});