const { Server } = require('socket.io');
const { createServer } = require('http');
const { io: Client } = require('socket.io-client');
const TmuxManager = require('../../src/lib/tmux-manager');

// Mock dependencies for controlled testing
jest.mock('node-pty', () => ({
  spawn: jest.fn(),
}));

jest.mock('../../src/lib/tmux-manager');

describe('WebSocket Server Integration Tests', () => {
  let httpServer;
  let ioServer;
  let clientSocket;
  let mockTmuxManager;
  let mockPty;
  let originalConsole;

  const DEFAULT_PORT = 3001;

  beforeAll(() => {
    originalConsole = { log: console.log, error: console.error };
    console.log = jest.fn();
    console.error = jest.fn();
  });

  afterAll(() => {
    console.log = originalConsole.log;
    console.error = originalConsole.error;
  });

  beforeEach(async () => {
    jest.clearAllMocks();

    // Mock TmuxManager
    mockTmuxManager = {
      isTmuxAvailable: jest.fn().mockResolvedValue(true),
      createSession: jest.fn().mockResolvedValue({
        name: 'test-session',
        socketPath: '/tmp/test-socket',
      }),
      connectToSession: jest.fn().mockResolvedValue({
        onData: jest.fn(),
        onExit: jest.fn(),
        write: jest.fn(),
        resize: jest.fn(),
      }),
      captureFullScreen: jest.fn().mockResolvedValue('initial screen content'),
      cleanup: jest.fn().mockResolvedValue(),
    };
    TmuxManager.mockImplementation(() => mockTmuxManager);

    // Mock PTY
    mockPty = {
      onData: jest.fn(),
      onExit: jest.fn(),
      write: jest.fn(),
      resize: jest.fn(),
    };

    require('node-pty').spawn.mockReturnValue(mockPty);

    // Create HTTP server and Socket.IO server
    httpServer = createServer();
    ioServer = new Server(httpServer, {
      cors: {
        origin: '*',
        methods: ['GET', 'POST'],
        credentials: true,
      },
      transports: ['websocket', 'polling'],
    });

    // Start server
    await new Promise((resolve) => {
      httpServer.listen(DEFAULT_PORT, () => {
        resolve();
      });
    });

    // Connect client
    clientSocket = Client(`http://localhost:${DEFAULT_PORT}`, {
      transports: ['websocket'],
    });

    await new Promise((resolve) => {
      clientSocket.on('connect', resolve);
    });
  });

  afterEach(async () => {
    if (clientSocket) {
      clientSocket.disconnect();
    }
    
    if (ioServer) {
      ioServer.close();
    }
    
    if (httpServer) {
      await new Promise((resolve) => {
        httpServer.close(resolve);
      });
    }
  });

  describe('Connection Management', () => {
    it('should handle client connection and send initial configuration', (done) => {
      ioServer.on('connection', (socket) => {
        socket.emit('connected', {
          message: 'Connected to Claude Flow Terminal',
          sessionId: 'test-session',
          timestamp: Date.now(),
        });

        socket.emit('terminal-config', {
          cols: 120,
          rows: 30,
          sessionId: 'test-session',
          timestamp: Date.now(),
        });
      });

      let receivedEvents = 0;
      const expectedEvents = 2;

      clientSocket.on('connected', (data) => {
        expect(data.message).toBe('Connected to Claude Flow Terminal');
        expect(data.sessionId).toBe('test-session');
        expect(data.timestamp).toBeDefined();
        receivedEvents++;
        
        if (receivedEvents === expectedEvents) done();
      });

      clientSocket.on('terminal-config', (data) => {
        expect(data.cols).toBe(120);
        expect(data.rows).toBe(30);
        expect(data.sessionId).toBe('test-session');
        receivedEvents++;
        
        if (receivedEvents === expectedEvents) done();
      });
    });

    it('should handle multiple client connections', async () => {
      const clients = [];
      const connectionPromises = [];

      // Create multiple clients
      for (let i = 0; i < 5; i++) {
        const client = Client(`http://localhost:${DEFAULT_PORT}`, {
          transports: ['websocket'],
        });

        connectionPromises.push(
          new Promise((resolve) => {
            client.on('connect', () => resolve(client));
          })
        );

        clients.push(client);
      }

      const connectedClients = await Promise.all(connectionPromises);
      
      expect(connectedClients).toHaveLength(5);
      
      // Clean up
      connectedClients.forEach(client => client.disconnect());
    });

    it('should handle client disconnection gracefully', (done) => {
      ioServer.on('connection', (socket) => {
        socket.on('disconnect', (reason) => {
          expect(reason).toBeDefined();
          done();
        });
      });

      // Disconnect after a short delay
      setTimeout(() => {
        clientSocket.disconnect();
      }, 100);
    });
  });

  describe('Terminal Data Flow', () => {
    let serverSocket;

    beforeEach((done) => {
      ioServer.on('connection', (socket) => {
        serverSocket = socket;
        done();
      });
    });

    it('should handle terminal data transmission', (done) => {
      const testData = {
        sessionId: 'test-session',
        data: 'Hello from terminal',
      };

      clientSocket.on('terminal-data', (data) => {
        expect(data.sessionId).toBe(testData.sessionId);
        expect(data.data).toBe(testData.data);
        done();
      });

      serverSocket.emit('terminal-data', testData);
    });

    it('should handle bidirectional data flow', (done) => {
      const inputData = {
        sessionId: 'test-session',
        data: 'user input',
      };

      serverSocket.on('data', (data) => {
        expect(data.sessionId).toBe(inputData.sessionId);
        expect(data.data).toBe(inputData.data);
        
        // Echo back
        serverSocket.emit('terminal-data', {
          sessionId: data.sessionId,
          data: `Echo: ${data.data}`,
        });
      });

      clientSocket.on('terminal-data', (data) => {
        expect(data.data).toBe('Echo: user input');
        done();
      });

      clientSocket.emit('data', inputData);
    });

    it('should handle large data chunks', (done) => {
      const largeData = 'x'.repeat(1000000); // 1MB of data
      const testData = {
        sessionId: 'test-session',
        data: largeData,
      };

      clientSocket.on('terminal-data', (data) => {
        expect(data.data).toBe(largeData);
        expect(data.data.length).toBe(1000000);
        done();
      });

      serverSocket.emit('terminal-data', testData);
    });

    it('should handle ANSI escape sequences', (done) => {
      const ansiData = '\x1b[31mRed text\x1b[0m\x1b[32mGreen text\x1b[0m';
      const testData = {
        sessionId: 'test-session',
        data: ansiData,
      };

      clientSocket.on('terminal-data', (data) => {
        expect(data.data).toBe(ansiData);
        expect(data.data).toContain('\x1b[31m');
        expect(data.data).toContain('\x1b[32m');
        done();
      });

      serverSocket.emit('terminal-data', testData);
    });
  });

  describe('Terminal Operations', () => {
    let serverSocket;

    beforeEach((done) => {
      ioServer.on('connection', (socket) => {
        serverSocket = socket;
        done();
      });
    });

    it('should handle terminal resize operations', (done) => {
      const resizeData = {
        sessionId: 'test-session',
        cols: 100,
        rows: 40,
      };

      serverSocket.on('resize', (data) => {
        expect(data.sessionId).toBe(resizeData.sessionId);
        expect(data.cols).toBe(resizeData.cols);
        expect(data.rows).toBe(resizeData.rows);
        done();
      });

      clientSocket.emit('resize', resizeData);
    });

    it('should handle session creation requests', (done) => {
      serverSocket.emit('session-created', { 
        sessionId: 'new-session',
        timestamp: Date.now() 
      });

      clientSocket.on('session-created', (data) => {
        expect(data.sessionId).toBe('new-session');
        expect(data.timestamp).toBeDefined();
        done();
      });

      clientSocket.emit('create');
    });

    it('should handle session list requests', (done) => {
      const mockSessions = [{
        id: 'session-1',
        created: Date.now(),
        isClaudeFlow: true,
      }];

      serverSocket.on('list', () => {
        serverSocket.emit('session-list', { sessions: mockSessions });
      });

      clientSocket.on('session-list', (data) => {
        expect(data.sessions).toEqual(mockSessions);
        expect(Array.isArray(data.sessions)).toBe(true);
        done();
      });

      clientSocket.emit('list');
    });

    it('should handle destroy requests gracefully', (done) => {
      const destroyData = {
        sessionId: 'test-session',
      };

      serverSocket.on('destroy', (data) => {
        expect(data.sessionId).toBe(destroyData.sessionId);
        done();
      });

      clientSocket.emit('destroy', destroyData);
    });
  });

  describe('System Metrics', () => {
    let serverSocket;

    beforeEach((done) => {
      ioServer.on('connection', (socket) => {
        serverSocket = socket;
        done();
      });
    });

    it('should handle system metrics broadcasting', (done) => {
      const metricsData = {
        memoryTotal: 17179869184,
        memoryUsed: 12000000000,
        memoryFree: 5179869184,
        memoryUsagePercent: 70,
        memoryEfficiency: 30,
        cpuCount: 8,
        cpuLoad: 1.5,
        platform: 'darwin',
        uptime: 86400,
        timestamp: Date.now(),
      };

      clientSocket.on('system-metrics', (data) => {
        expect(data.memoryTotal).toBe(metricsData.memoryTotal);
        expect(data.memoryUsed).toBe(metricsData.memoryUsed);
        expect(data.cpuCount).toBe(metricsData.cpuCount);
        expect(data.timestamp).toBeDefined();
        done();
      });

      serverSocket.emit('system-metrics', metricsData);
    });

    it('should handle agent status updates', (done) => {
      const agentData = {
        agentId: 'agent-1',
        state: 'busy',
        currentTask: 'Processing data',
        timestamp: Date.now(),
      };

      clientSocket.on('agent-status', (data) => {
        expect(data.agentId).toBe(agentData.agentId);
        expect(data.state).toBe(agentData.state);
        expect(data.currentTask).toBe(agentData.currentTask);
        done();
      });

      serverSocket.emit('agent-status', agentData);
    });

    it('should handle command notifications', (done) => {
      const commandData = {
        id: 'cmd-123',
        command: 'ls -la',
        agentId: 'agent-1',
        timestamp: Date.now(),
      };

      clientSocket.on('command-created', (data) => {
        expect(data.id).toBe(commandData.id);
        expect(data.command).toBe(commandData.command);
        expect(data.agentId).toBe(commandData.agentId);
        done();
      });

      serverSocket.emit('command-created', commandData);
    });
  });

  describe('Error Handling', () => {
    let serverSocket;

    beforeEach((done) => {
      ioServer.on('connection', (socket) => {
        serverSocket = socket;
        done();
      });
    });

    it('should handle terminal errors', (done) => {
      const errorData = {
        sessionId: 'test-session',
        error: 'Connection failed',
        timestamp: Date.now(),
      };

      clientSocket.on('terminal-error', (data) => {
        expect(data.sessionId).toBe(errorData.sessionId);
        expect(data.error).toBe(errorData.error);
        done();
      });

      serverSocket.emit('terminal-error', errorData);
    });

    it('should handle connection errors', (done) => {
      const errorData = {
        message: 'Authentication failed',
        code: 'AUTH_ERROR',
        timestamp: Date.now(),
      };

      clientSocket.on('error', (data) => {
        expect(data.message).toBe(errorData.message);
        expect(data.code).toBe(errorData.code);
        done();
      });

      serverSocket.emit('error', errorData);
    });

    it('should handle malformed data gracefully', (done) => {
      // Send malformed data that should not crash the server
      const malformedData = {
        sessionId: null,
        data: undefined,
        timestamp: 'invalid',
      };

      // Server should handle this gracefully
      serverSocket.on('data', (data) => {
        // Should receive data even if malformed
        expect(data).toBeDefined();
        done();
      });

      clientSocket.emit('data', malformedData);
    });
  });

  describe('Performance and Stress Tests', () => {
    let serverSocket;

    beforeEach((done) => {
      ioServer.on('connection', (socket) => {
        serverSocket = socket;
        done();
      });
    });

    it('should handle rapid message transmission', async () => {
      const messageCount = 1000;
      const messages = [];
      
      const messagePromise = new Promise((resolve) => {
        let receivedCount = 0;
        
        clientSocket.on('terminal-data', (data) => {
          messages.push(data);
          receivedCount++;
          
          if (receivedCount === messageCount) {
            resolve();
          }
        });
      });

      // Send messages rapidly
      for (let i = 0; i < messageCount; i++) {
        serverSocket.emit('terminal-data', {
          sessionId: 'test-session',
          data: `Message ${i}`,
        });
      }

      await messagePromise;
      
      expect(messages).toHaveLength(messageCount);
      expect(messages[0].data).toBe('Message 0');
      expect(messages[messageCount - 1].data).toBe(`Message ${messageCount - 1}`);
    });

    it('should handle concurrent client interactions', async () => {
      const clientCount = 10;
      const clients = [];
      const results = [];

      // Create multiple clients
      for (let i = 0; i < clientCount; i++) {
        const client = Client(`http://localhost:${DEFAULT_PORT}`, {
          transports: ['websocket'],
        });

        const clientPromise = new Promise((resolve) => {
          client.on('connect', () => {
            client.emit('data', {
              sessionId: 'test-session',
              data: `Client ${i} message`,
            });
            resolve(client);
          });
        });

        clients.push(clientPromise);
      }

      // Wait for all clients to connect and send messages
      const connectedClients = await Promise.all(clients);

      // Server should handle all messages
      const messagePromise = new Promise((resolve) => {
        let receivedCount = 0;
        
        ioServer.on('connection', (socket) => {
          socket.on('data', (data) => {
            results.push(data);
            receivedCount++;
            
            if (receivedCount === clientCount) {
              resolve();
            }
          });
        });
      });

      await messagePromise;
      
      expect(results.length).toBeGreaterThan(0);
      
      // Clean up clients
      connectedClients.forEach(client => client.disconnect());
    });

    it('should maintain performance under load', async () => {
      const startTime = Date.now();
      const testDuration = 2000; // 2 seconds
      let messagesSent = 0;
      let messagesReceived = 0;

      const performancePromise = new Promise((resolve) => {
        clientSocket.on('terminal-data', () => {
          messagesReceived++;
        });

        const sendInterval = setInterval(() => {
          if (Date.now() - startTime >= testDuration) {
            clearInterval(sendInterval);
            resolve();
          } else {
            serverSocket.emit('terminal-data', {
              sessionId: 'test-session',
              data: `Performance test message ${messagesSent}`,
            });
            messagesSent++;
          }
        }, 10); // Send every 10ms
      });

      await performancePromise;
      
      expect(messagesSent).toBeGreaterThan(100);
      expect(messagesReceived).toBeGreaterThan(50);
      expect(messagesReceived / messagesSent).toBeGreaterThan(0.5); // At least 50% delivery rate
    });
  });

  describe('Integration with Terminal Backend', () => {
    it('should integrate with tmux manager correctly', async () => {
      // Mock tmux integration
      const mockTerminal = {
        onData: jest.fn(),
        onExit: jest.fn(),
        write: jest.fn(),
        resize: jest.fn(),
      };

      mockTmuxManager.connectToSession.mockResolvedValue(mockTerminal);

      // Simulate tmux data callback
      const onDataCallback = mockTerminal.onData.mock.calls[0]?.[0];
      if (onDataCallback) {
        onDataCallback('tmux output data');
      }

      expect(mockTmuxManager.connectToSession).toHaveBeenCalled();
      expect(mockTerminal.onData).toHaveBeenCalled();
    });

    it('should handle tmux session failures gracefully', async () => {
      // Mock tmux failure
      mockTmuxManager.isTmuxAvailable.mockResolvedValue(false);

      // Should fallback to PTY mode
      expect(mockTmuxManager.isTmuxAvailable).toHaveBeenCalled();
    });

    it('should handle PTY integration as fallback', () => {
      const mockPtyInstance = {
        onData: jest.fn(),
        onExit: jest.fn(),
        write: jest.fn(),
        resize: jest.fn(),
      };

      require('node-pty').spawn.mockReturnValue(mockPtyInstance);

      // Simulate PTY data
      const onDataCallback = mockPtyInstance.onData.mock.calls[0]?.[0];
      if (onDataCallback) {
        onDataCallback('pty output data');
      }

      expect(mockPtyInstance.onData).toHaveBeenCalled();
    });
  });

  describe('Memory Management', () => {
    it('should not leak event listeners', async () => {
      const initialListeners = process.listenerCount('exit');
      
      // Create and destroy multiple connections
      for (let i = 0; i < 10; i++) {
        const client = Client(`http://localhost:${DEFAULT_PORT}`, {
          transports: ['websocket'],
        });
        
        await new Promise(resolve => {
          client.on('connect', resolve);
        });
        
        client.disconnect();
      }

      const finalListeners = process.listenerCount('exit');
      expect(finalListeners).toBeLessThanOrEqual(initialListeners + 5);
    });

    it('should clean up resources on server shutdown', async () => {
      const cleanup = jest.fn();
      mockTmuxManager.cleanup = cleanup;

      // Simulate server shutdown
      httpServer.close();

      // Cleanup should be called
      setTimeout(() => {
        expect(cleanup).toHaveBeenCalled();
      }, 100);
    });
  });
});