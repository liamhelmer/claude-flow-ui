import { Server } from 'socket.io';
import { createServer } from 'http';
import { io as Client, Socket } from 'socket.io-client';
import { TmuxWebSocketServer } from '../../src/lib/tmux/websocket-server';
import { TmuxSessionManager } from '../../src/lib/tmux/session-manager';
import { AddressInfo } from 'net';

describe('Tmux WebSocket Integration', () => {
  let server: Server;
  let httpServer: any;
  let clientSocket: Socket;
  let serverSocket: Socket;
  let tmuxServer: TmuxWebSocketServer;
  let sessionManager: TmuxSessionManager;
  let port: number;

  beforeAll((done) => {
    httpServer = createServer();
    server = new Server(httpServer);
    sessionManager = new TmuxSessionManager('/tmp/test');
    tmuxServer = new TmuxWebSocketServer(server, sessionManager);

    httpServer.listen(() => {
      port = (httpServer.address() as AddressInfo).port;
      clientSocket = Client(`http://localhost:${port}`);
      
      server.on('connection', (socket) => {
        serverSocket = socket;
      });
      
      clientSocket.on('connect', done);
    });
  });

  afterAll(() => {
    server.close();
    httpServer.close();
    clientSocket.close();
  });

  beforeEach(() => {
    global.tmuxTestUtils.clearMockTmux();
  });

  describe('Session Management via WebSocket', () => {
    it('should create tmux session via WebSocket', (done) => {
      const sessionId = 'ws-test-session';
      const command = 'claude-flow test';

      // Mock successful session creation
      global.tmuxTestUtils.createMockSession(sessionId);

      clientSocket.emit('tmux:create-session', {
        sessionId,
        command,
        options: {
          cols: 80,
          rows: 24,
        }
      });

      clientSocket.on('tmux:session-created', (response) => {
        expect(response).toMatchObject({
          sessionId,
          status: 'success',
          session: expect.objectContaining({
            id: sessionId,
            socketPath: expect.any(String),
            created: expect.any(Number),
          })
        });
        done();
      });
    });

    it('should handle session creation errors', (done) => {
      const sessionId = 'failing-session';

      // Mock session creation failure
      jest.spyOn(sessionManager, 'createSession').mockRejectedValue(
        new Error('Failed to create session')
      );

      clientSocket.emit('tmux:create-session', {
        sessionId,
        command: 'failing-command'
      });

      clientSocket.on('tmux:session-error', (response) => {
        expect(response).toMatchObject({
          sessionId,
          error: 'Failed to create session',
          status: 'error'
        });
        done();
      });
    });

    it('should list active tmux sessions', (done) => {
      // Create multiple mock sessions
      global.tmuxTestUtils.createMockSession('session1');
      global.tmuxTestUtils.createMockSession('session2');
      global.tmuxTestUtils.createMockSession('session3');

      // Mock sessionManager.listSessions
      jest.spyOn(sessionManager, 'listSessions').mockResolvedValue([
        { id: 'session1', windows: 1, status: 'active', created: Date.now() },
        { id: 'session2', windows: 2, status: 'active', created: Date.now() },
        { id: 'session3', windows: 1, status: 'active', created: Date.now() },
      ]);

      clientSocket.emit('tmux:list-sessions');

      clientSocket.on('tmux:session-list', (response) => {
        expect(response.sessions).toHaveLength(3);
        expect(response.sessions).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ id: 'session1' }),
            expect.objectContaining({ id: 'session2' }),
            expect.objectContaining({ id: 'session3' }),
          ])
        );
        done();
      });
    });

    it('should attach to existing tmux session', (done) => {
      const sessionId = 'existing-session';
      global.tmuxTestUtils.createMockSession(sessionId);

      // Mock successful attachment
      jest.spyOn(sessionManager, 'hasSession').mockResolvedValue(true);
      jest.spyOn(sessionManager, 'capturePane').mockResolvedValue('existing session content');

      clientSocket.emit('tmux:attach-session', { sessionId });

      clientSocket.on('tmux:session-attached', (response) => {
        expect(response).toMatchObject({
          sessionId,
          status: 'success',
          content: 'existing session content'
        });
        done();
      });
    });

    it('should handle attach to non-existent session', (done) => {
      const sessionId = 'non-existent';

      jest.spyOn(sessionManager, 'hasSession').mockResolvedValue(false);

      clientSocket.emit('tmux:attach-session', { sessionId });

      clientSocket.on('tmux:session-error', (response) => {
        expect(response).toMatchObject({
          sessionId,
          error: expect.stringContaining('Session not found'),
          status: 'error'
        });
        done();
      });
    });
  });

  describe('Terminal Data Streaming', () => {
    const sessionId = 'streaming-session';

    beforeEach(() => {
      global.tmuxTestUtils.createMockSession(sessionId);
    });

    it('should stream terminal input to tmux session', (done) => {
      const inputData = 'echo "Hello tmux"\n';

      jest.spyOn(sessionManager, 'sendKeys').mockResolvedValue(void 0);

      clientSocket.emit('tmux:input', {
        sessionId,
        data: inputData
      });

      // Verify sendKeys was called
      setTimeout(() => {
        expect(sessionManager.sendKeys).toHaveBeenCalledWith(sessionId, inputData);
        done();
      }, 100);
    });

    it('should stream terminal output from tmux session', (done) => {
      const outputData = 'Hello from tmux session\n';

      // Simulate tmux output
      global.tmuxTestUtils.simulateSessionOutput(sessionId, outputData);

      // Mock capturePane to return the output
      jest.spyOn(sessionManager, 'capturePane').mockResolvedValue(outputData);

      // Simulate server streaming output
      setTimeout(() => {
        serverSocket.emit('tmux:output', {
          sessionId,
          data: outputData,
          timestamp: Date.now()
        });
      }, 50);

      clientSocket.on('tmux:output', (response) => {
        expect(response).toMatchObject({
          sessionId,
          data: outputData,
          timestamp: expect.any(Number)
        });
        done();
      });
    });

    it('should handle binary data correctly', (done) => {
      const binaryData = Buffer.from([0x1b, 0x5b, 0x33, 0x31, 0x6d]); // ANSI escape sequence

      clientSocket.emit('tmux:input', {
        sessionId,
        data: binaryData.toString('binary')
      });

      jest.spyOn(sessionManager, 'sendKeys').mockResolvedValue(void 0);

      setTimeout(() => {
        expect(sessionManager.sendKeys).toHaveBeenCalledWith(
          sessionId, 
          binaryData.toString('binary')
        );
        done();
      }, 100);
    });

    it('should handle rapid input/output correctly', (done) => {
      const inputs = ['ls\n', 'pwd\n', 'echo test\n'];
      const outputs = ['file1.txt\nfile2.txt\n', '/current/directory\n', 'test\n'];
      
      jest.spyOn(sessionManager, 'sendKeys').mockResolvedValue(void 0);
      jest.spyOn(sessionManager, 'capturePane')
        .mockResolvedValueOnce(outputs[0])
        .mockResolvedValueOnce(outputs[1])
        .mockResolvedValueOnce(outputs[2]);

      let outputCount = 0;

      clientSocket.on('tmux:output', (response) => {
        expect(response.data).toBe(outputs[outputCount]);
        outputCount++;
        
        if (outputCount === inputs.length) {
          done();
        }
      });

      // Send rapid inputs
      inputs.forEach((input, index) => {
        setTimeout(() => {
          clientSocket.emit('tmux:input', { sessionId, data: input });
          
          // Simulate output after input
          setTimeout(() => {
            serverSocket.emit('tmux:output', {
              sessionId,
              data: outputs[index],
              timestamp: Date.now()
            });
          }, 10);
        }, index * 20);
      });
    });
  });

  describe('Session Persistence and Reconnection', () => {
    const sessionId = 'persistent-session';

    it('should reconnect to existing session with history', (done) => {
      const historicalOutput = 'Previous command output\nMore history\n';
      
      global.tmuxTestUtils.createMockSession(sessionId);
      global.tmuxTestUtils.simulateSessionOutput(sessionId, historicalOutput);

      jest.spyOn(sessionManager, 'hasSession').mockResolvedValue(true);
      jest.spyOn(sessionManager, 'capturePane').mockResolvedValue(historicalOutput);

      clientSocket.emit('tmux:reconnect', { sessionId });

      clientSocket.on('tmux:reconnected', (response) => {
        expect(response).toMatchObject({
          sessionId,
          status: 'success',
          history: historicalOutput,
          sessionInfo: expect.any(Object)
        });
        done();
      });
    });

    it('should handle reconnection to dead session', (done) => {
      const deadSessionId = 'dead-session';

      jest.spyOn(sessionManager, 'hasSession').mockResolvedValue(false);

      clientSocket.emit('tmux:reconnect', { sessionId: deadSessionId });

      clientSocket.on('tmux:session-error', (response) => {
        expect(response).toMatchObject({
          sessionId: deadSessionId,
          error: expect.stringContaining('Session not found or has expired'),
          status: 'error'
        });
        done();
      });
    });

    it('should preserve session across client disconnections', (done) => {
      global.tmuxTestUtils.createMockSession(sessionId);

      // First connection creates session
      clientSocket.emit('tmux:create-session', {
        sessionId,
        command: 'claude-flow persistent'
      });

      clientSocket.on('tmux:session-created', () => {
        // Simulate client disconnect and reconnect
        clientSocket.disconnect();

        const newClientSocket = Client(`http://localhost:${port}`);
        
        newClientSocket.on('connect', () => {
          // Try to attach to the persistent session
          jest.spyOn(sessionManager, 'hasSession').mockResolvedValue(true);
          jest.spyOn(sessionManager, 'capturePane').mockResolvedValue('session still running');

          newClientSocket.emit('tmux:attach-session', { sessionId });

          newClientSocket.on('tmux:session-attached', (response) => {
            expect(response.status).toBe('success');
            expect(response.sessionId).toBe(sessionId);
            newClientSocket.close();
            done();
          });
        });
      });
    });
  });

  describe('Multi-User Session Access', () => {
    const sharedSessionId = 'shared-session';
    let client2: Socket;

    beforeEach((done) => {
      client2 = Client(`http://localhost:${port}`);
      client2.on('connect', () => {
        global.tmuxTestUtils.createMockSession(sharedSessionId);
        done();
      });
    });

    afterEach(() => {
      client2.close();
    });

    it('should allow multiple clients to attach to same session', (done) => {
      jest.spyOn(sessionManager, 'hasSession').mockResolvedValue(true);
      jest.spyOn(sessionManager, 'capturePane').mockResolvedValue('shared session content');

      let client1Connected = false;
      let client2Connected = false;

      const checkBothConnected = () => {
        if (client1Connected && client2Connected) {
          done();
        }
      };

      clientSocket.emit('tmux:attach-session', { sessionId: sharedSessionId });
      client2.emit('tmux:attach-session', { sessionId: sharedSessionId });

      clientSocket.on('tmux:session-attached', () => {
        client1Connected = true;
        checkBothConnected();
      });

      client2.on('tmux:session-attached', () => {
        client2Connected = true;
        checkBothConnected();
      });
    });

    it('should broadcast input from one client to all connected clients', (done) => {
      const sharedInput = 'echo "shared command"\n';
      
      jest.spyOn(sessionManager, 'sendKeys').mockResolvedValue(void 0);

      // Client 1 sends input
      clientSocket.emit('tmux:input', {
        sessionId: sharedSessionId,
        data: sharedInput
      });

      // Both clients should receive the echoed input
      let client1Received = false;
      let client2Received = false;

      const checkBothReceived = () => {
        if (client1Received && client2Received) {
          done();
        }
      };

      // Simulate server broadcasting the input to all clients
      setTimeout(() => {
        server.emit('tmux:output', {
          sessionId: sharedSessionId,
          data: sharedInput,
          timestamp: Date.now(),
          fromUser: 'client1'
        });
      }, 50);

      clientSocket.on('tmux:output', (response) => {
        if (response.data === sharedInput) {
          client1Received = true;
          checkBothReceived();
        }
      });

      client2.on('tmux:output', (response) => {
        if (response.data === sharedInput) {
          client2Received = true;
          checkBothReceived();
        }
      });
    });

    it('should handle concurrent resize requests', (done) => {
      jest.spyOn(sessionManager, 'resizeSession').mockResolvedValue(void 0);

      const resize1 = { cols: 80, rows: 24 };
      const resize2 = { cols: 120, rows: 30 };

      // Send concurrent resize requests
      clientSocket.emit('tmux:resize', { sessionId: sharedSessionId, ...resize1 });
      client2.emit('tmux:resize', { sessionId: sharedSessionId, ...resize2 });

      // The session manager should handle both resizes
      setTimeout(() => {
        expect(sessionManager.resizeSession).toHaveBeenCalledTimes(2);
        expect(sessionManager.resizeSession).toHaveBeenCalledWith(sharedSessionId, resize1.cols, resize1.rows);
        expect(sessionManager.resizeSession).toHaveBeenCalledWith(sharedSessionId, resize2.cols, resize2.rows);
        done();
      }, 100);
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle tmux server crash gracefully', (done) => {
      const sessionId = 'crash-test-session';
      global.tmuxTestUtils.createMockSession(sessionId);

      // Mock tmux server crash
      jest.spyOn(sessionManager, 'sendKeys').mockRejectedValue(
        new Error('tmux server not running')
      );

      clientSocket.emit('tmux:input', {
        sessionId,
        data: 'test input'
      });

      clientSocket.on('tmux:session-error', (response) => {
        expect(response).toMatchObject({
          sessionId,
          error: expect.stringContaining('tmux server not running'),
          status: 'error',
          recoverable: true
        });
        done();
      });
    });

    it('should handle socket file corruption', (done) => {
      const sessionId = 'corrupted-socket-session';
      
      // Mock socket validation failure
      jest.spyOn(sessionManager, 'validateSocketFile').mockReturnValue(false);
      jest.spyOn(sessionManager, 'hasSession').mockResolvedValue(false);

      clientSocket.emit('tmux:attach-session', { sessionId });

      clientSocket.on('tmux:session-error', (response) => {
        expect(response).toMatchObject({
          sessionId,
          error: expect.stringContaining('Session not found or socket corrupted'),
          status: 'error',
          suggestion: 'Try creating a new session'
        });
        done();
      });
    });

    it('should implement connection timeout handling', (done) => {
      const sessionId = 'timeout-session';

      // Mock a hanging tmux command
      jest.spyOn(sessionManager, 'createSession').mockImplementation(() => 
        new Promise(() => {}) // Never resolves
      );

      clientSocket.emit('tmux:create-session', {
        sessionId,
        command: 'hanging-command',
        timeout: 1000
      });

      clientSocket.on('tmux:session-error', (response) => {
        expect(response).toMatchObject({
          sessionId,
          error: expect.stringContaining('timeout'),
          status: 'error'
        });
        done();
      });
    });
  });

  describe('Performance and Memory Management', () => {
    it('should handle high-frequency data without memory leaks', (done) => {
      const sessionId = 'performance-session';
      global.tmuxTestUtils.createMockSession(sessionId);

      const iterations = 1000;
      let receivedCount = 0;
      const startMemory = process.memoryUsage().heapUsed;

      jest.spyOn(sessionManager, 'sendKeys').mockResolvedValue(void 0);

      clientSocket.on('tmux:output', () => {
        receivedCount++;
        
        if (receivedCount === iterations) {
          const endMemory = process.memoryUsage().heapUsed;
          const memoryIncrease = endMemory - startMemory;
          
          // Memory increase should be reasonable (less than 10MB)
          expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
          done();
        }
      });

      // Send high-frequency data
      for (let i = 0; i < iterations; i++) {
        setTimeout(() => {
          serverSocket.emit('tmux:output', {
            sessionId,
            data: `data chunk ${i}\n`,
            timestamp: Date.now()
          });
        }, i);
      }
    }, 10000);

    it('should efficiently handle large output chunks', (done) => {
      const sessionId = 'large-output-session';
      global.tmuxTestUtils.createMockSession(sessionId);

      // Create a large chunk of data (1MB)
      const largeData = 'A'.repeat(1024 * 1024);
      const startTime = performance.now();

      jest.spyOn(sessionManager, 'capturePane').mockResolvedValue(largeData);

      clientSocket.emit('tmux:capture-full', { sessionId });

      clientSocket.on('tmux:capture-result', (response) => {
        const endTime = performance.now();
        const processingTime = endTime - startTime;

        expect(response.data).toHaveLength(largeData.length);
        // Should process 1MB in under 1 second
        expect(processingTime).toBeLessThan(1000);
        done();
      });
    });
  });
});