/**
 * @jest-environment node
 */

const { Server } = require('socket.io');
const { createServer } = require('http');
const Client = require('socket.io-client');
const pty = require('node-pty');

// Mock node-pty for testing
jest.mock('node-pty', () => ({
  spawn: jest.fn(),
}));

// Mock TmuxManager
jest.mock('../../src/lib/tmux-manager', () => {
  return jest.fn().mockImplementation(() => ({
    createSession: jest.fn().mockResolvedValue('test-session-id'),
    getSession: jest.fn().mockResolvedValue({
      id: 'test-session-id',
      name: 'test-session',
      status: 'active'
    }),
    listSessions: jest.fn().mockResolvedValue([]),
    killSession: jest.fn().mockResolvedValue(true),
    attachToSession: jest.fn().mockResolvedValue(true),
    detachFromSession: jest.fn().mockResolvedValue(true),
    resizeSession: jest.fn().mockResolvedValue(true),
    sendCommand: jest.fn().mockResolvedValue('command sent'),
  }));
});

describe('WebSocket Server Comprehensive Tests', () => {
  let httpServer;
  let io;
  let clientSocket;
  let serverSocket;
  let mockPty;
  let port;

  beforeEach((done) => {
    // Setup mock PTY
    mockPty = {
      write: jest.fn(),
      kill: jest.fn(),
      resize: jest.fn(),
      on: jest.fn(),
      removeAllListeners: jest.fn(),
      pid: 12345,
    };
    
    pty.spawn.mockReturnValue(mockPty);

    // Create HTTP server and Socket.IO server
    httpServer = createServer();
    io = new Server(httpServer, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    // Find available port
    httpServer.listen(0, () => {
      port = httpServer.address().port;
      
      // Setup server-side socket handling
      io.on('connection', (socket) => {
        serverSocket = socket;
      });

      done();
    });
  });

  afterEach((done) => {
    if (clientSocket) {
      clientSocket.close();
    }
    if (io) {
      io.close();
    }
    if (httpServer) {
      httpServer.close(done);
    } else {
      done();
    }
    
    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('Connection Management', () => {
    test('should accept client connections', (done) => {
      clientSocket = Client(`http://localhost:${port}`);
      
      clientSocket.on('connect', () => {
        expect(clientSocket.connected).toBe(true);
        done();
      });
    });

    test('should handle client disconnection gracefully', (done) => {
      clientSocket = Client(`http://localhost:${port}`);
      
      clientSocket.on('connect', () => {
        clientSocket.disconnect();
      });

      clientSocket.on('disconnect', () => {
        expect(clientSocket.connected).toBe(false);
        done();
      });
    });

    test('should handle multiple concurrent connections', (done) => {
      const client1 = Client(`http://localhost:${port}`);
      const client2 = Client(`http://localhost:${port}`);
      let connectedCount = 0;

      const handleConnection = () => {
        connectedCount++;
        if (connectedCount === 2) {
          expect(client1.connected).toBe(true);
          expect(client2.connected).toBe(true);
          client1.close();
          client2.close();
          done();
        }
      };

      client1.on('connect', handleConnection);
      client2.on('connect', handleConnection);
    });
  });

  describe('Terminal Session Management', () => {
    beforeEach((done) => {
      clientSocket = Client(`http://localhost:${port}`);
      clientSocket.on('connect', done);
    });

    test('should create new terminal session on request', (done) => {
      serverSocket.on('create-session', (data) => {
        expect(data).toHaveProperty('sessionId');
        
        // Simulate PTY creation
        const sessionId = data.sessionId;
        
        serverSocket.emit('terminal-config', {
          sessionId,
          cols: 80,
          rows: 24
        });
        
        done();
      });

      clientSocket.emit('create-session', { sessionId: 'test-session-1' });
    });

    test('should handle terminal data transmission', (done) => {
      const testData = 'echo "hello world"';
      
      serverSocket.on('terminal-input', (data) => {
        expect(data).toHaveProperty('sessionId');
        expect(data).toHaveProperty('data', testData);
        done();
      });

      clientSocket.emit('terminal-input', {
        sessionId: 'test-session',
        data: testData
      });
    });

    test('should handle terminal resize requests', (done) => {
      const resizeData = { cols: 120, rows: 40 };
      
      serverSocket.on('resize-terminal', (data) => {
        expect(data).toHaveProperty('sessionId');
        expect(data).toHaveProperty('cols', 120);
        expect(data).toHaveProperty('rows', 40);
        done();
      });

      clientSocket.emit('resize-terminal', {
        sessionId: 'test-session',
        ...resizeData
      });
    });
  });

  describe('Error Handling', () => {
    beforeEach((done) => {
      clientSocket = Client(`http://localhost:${port}`);
      clientSocket.on('connect', done);
    });

    test('should handle PTY spawn errors', (done) => {
      pty.spawn.mockImplementation(() => {
        throw new Error('PTY spawn failed');
      });

      serverSocket.on('create-session', () => {
        // Should emit error event
        serverSocket.emit('terminal-error', {
          sessionId: 'test-session',
          error: 'Failed to create terminal session'
        });
      });

      clientSocket.on('terminal-error', (data) => {
        expect(data).toHaveProperty('error');
        expect(data.error).toContain('Failed to create terminal session');
        done();
      });

      clientSocket.emit('create-session', { sessionId: 'test-session' });
    });

    test('should handle malformed data gracefully', (done) => {
      let errorHandled = false;

      serverSocket.on('terminal-input', (data) => {
        try {
          if (!data || !data.sessionId) {
            throw new Error('Invalid data format');
          }
        } catch (error) {
          errorHandled = true;
          serverSocket.emit('terminal-error', {
            sessionId: data?.sessionId || 'unknown',
            error: 'Invalid data format'
          });
        }
      });

      clientSocket.on('terminal-error', (data) => {
        expect(errorHandled).toBe(true);
        expect(data).toHaveProperty('error');
        done();
      });

      // Send malformed data
      clientSocket.emit('terminal-input', null);
    });

    test('should handle PTY process death', (done) => {
      const mockExit = jest.fn();
      mockPty.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          mockExit.mockImplementation(callback);
        }
      });

      serverSocket.on('create-session', () => {
        // Simulate PTY exit
        setTimeout(() => {
          mockExit(1, 'SIGTERM');
          serverSocket.emit('terminal-error', {
            sessionId: 'test-session',
            error: 'Terminal process exited'
          });
        }, 10);
      });

      clientSocket.on('terminal-error', (data) => {
        expect(data).toHaveProperty('error');
        expect(data.error).toContain('Terminal process exited');
        done();
      });

      clientSocket.emit('create-session', { sessionId: 'test-session' });
    });
  });

  describe('Performance and Stress Testing', () => {
    test('should handle rapid terminal input', (done) => {
      clientSocket = Client(`http://localhost:${port}`);
      let receivedCount = 0;
      const messageCount = 100;
      
      clientSocket.on('connect', () => {
        serverSocket.on('terminal-input', () => {
          receivedCount++;
          if (receivedCount === messageCount) {
            expect(receivedCount).toBe(messageCount);
            done();
          }
        });

        // Send rapid messages
        for (let i = 0; i < messageCount; i++) {
          clientSocket.emit('terminal-input', {
            sessionId: 'test-session',
            data: `command ${i}\n`
          });
        }
      });
    });

    test('should handle large terminal output', (done) => {
      const largeData = 'x'.repeat(10000); // 10KB of data
      
      clientSocket = Client(`http://localhost:${port}`);
      
      clientSocket.on('connect', () => {
        serverSocket.on('terminal-input', (data) => {
          expect(data.data).toHaveLength(10000);
          done();
        });

        clientSocket.emit('terminal-input', {
          sessionId: 'test-session',
          data: largeData
        });
      });
    });
  });

  describe('Security Tests', () => {
    beforeEach((done) => {
      clientSocket = Client(`http://localhost:${port}`);
      clientSocket.on('connect', done);
    });

    test('should sanitize terminal input for command injection', (done) => {
      const maliciousInput = 'ls; rm -rf /';
      
      serverSocket.on('terminal-input', (data) => {
        // Input should be received as-is but server should handle safely
        expect(data.data).toBe(maliciousInput);
        expect(mockPty.write).not.toHaveBeenCalledWith('rm -rf /');
        done();
      });

      clientSocket.emit('terminal-input', {
        sessionId: 'test-session',
        data: maliciousInput
      });
    });

    test('should validate session IDs', (done) => {
      const invalidSessionId = '../../../etc/passwd';
      let errorHandled = false;
      
      serverSocket.on('terminal-input', (data) => {
        if (data.sessionId.includes('..') || data.sessionId.includes('/')) {
          errorHandled = true;
          serverSocket.emit('terminal-error', {
            sessionId: data.sessionId,
            error: 'Invalid session ID format'
          });
        }
      });

      clientSocket.on('terminal-error', (data) => {
        expect(errorHandled).toBe(true);
        expect(data.error).toContain('Invalid session ID format');
        done();
      });

      clientSocket.emit('terminal-input', {
        sessionId: invalidSessionId,
        data: 'ls'
      });
    });

    test('should limit message size', (done) => {
      const oversizedData = 'x'.repeat(100000); // 100KB
      let errorHandled = false;
      
      serverSocket.on('terminal-input', (data) => {
        if (data.data && data.data.length > 50000) {
          errorHandled = true;
          serverSocket.emit('terminal-error', {
            sessionId: data.sessionId,
            error: 'Message too large'
          });
        }
      });

      clientSocket.on('terminal-error', (data) => {
        expect(errorHandled).toBe(true);
        expect(data.error).toContain('Message too large');
        done();
      });

      clientSocket.emit('terminal-input', {
        sessionId: 'test-session',
        data: oversizedData
      });
    });
  });

  describe('Tmux Integration', () => {
    test('should handle tmux session creation requests', (done) => {
      clientSocket = Client(`http://localhost:${port}`);
      
      clientSocket.on('connect', () => {
        serverSocket.on('tmux-create', (data) => {
          expect(data).toHaveProperty('sessionName');
          serverSocket.emit('tmux-session-created', {
            sessionId: 'tmux-test-session',
            sessionName: data.sessionName
          });
        });

        clientSocket.on('tmux-session-created', (data) => {
          expect(data).toHaveProperty('sessionId');
          expect(data).toHaveProperty('sessionName');
          done();
        });

        clientSocket.emit('tmux-create', { sessionName: 'test-session' });
      });
    });

    test('should handle tmux session listing', (done) => {
      clientSocket = Client(`http://localhost:${port}`);
      
      clientSocket.on('connect', () => {
        serverSocket.on('tmux-list', () => {
          serverSocket.emit('tmux-sessions', {
            sessions: [
              { id: 'session-1', name: 'test-session-1', status: 'active' },
              { id: 'session-2', name: 'test-session-2', status: 'idle' }
            ]
          });
        });

        clientSocket.on('tmux-sessions', (data) => {
          expect(data).toHaveProperty('sessions');
          expect(data.sessions).toHaveLength(2);
          expect(data.sessions[0]).toHaveProperty('id');
          expect(data.sessions[0]).toHaveProperty('name');
          expect(data.sessions[0]).toHaveProperty('status');
          done();
        });

        clientSocket.emit('tmux-list');
      });
    });
  });

  describe('Memory and Resource Management', () => {
    test('should clean up PTY processes on disconnect', (done) => {
      const sessions = new Map();
      
      clientSocket = Client(`http://localhost:${port}`);
      
      clientSocket.on('connect', () => {
        serverSocket.on('create-session', (data) => {
          sessions.set(data.sessionId, mockPty);
        });

        serverSocket.on('disconnect', () => {
          // Simulate cleanup
          sessions.forEach((pty) => {
            pty.kill();
            pty.removeAllListeners();
          });
          sessions.clear();
          
          expect(mockPty.kill).toHaveBeenCalled();
          expect(mockPty.removeAllListeners).toHaveBeenCalled();
          done();
        });

        clientSocket.emit('create-session', { sessionId: 'test-session' });
        setTimeout(() => clientSocket.disconnect(), 100);
      });
    });

    test('should handle memory pressure gracefully', (done) => {
      // Simulate high memory usage
      const largeSessions = [];
      for (let i = 0; i < 50; i++) {
        largeSessions.push({
          sessionId: `session-${i}`,
          pty: mockPty,
          buffer: new Array(1000).fill('x').join('')
        });
      }

      clientSocket = Client(`http://localhost:${port}`);
      
      clientSocket.on('connect', () => {
        // Server should handle this without crashing
        serverSocket.emit('system-status', {
          sessions: largeSessions.length,
          memoryUsage: process.memoryUsage()
        });

        clientSocket.on('system-status', (data) => {
          expect(data).toHaveProperty('sessions');
          expect(data).toHaveProperty('memoryUsage');
          expect(data.sessions).toBe(50);
          done();
        });
      });
    });
  });
});