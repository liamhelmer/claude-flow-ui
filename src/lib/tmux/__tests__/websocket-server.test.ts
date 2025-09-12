/**
 * Unit tests for TmuxWebSocketServer
 */

import { Server as HTTPServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import TmuxWebSocketServer, { TmuxWebSocketServerOptions } from '../websocket-server';
import TmuxSessionManager from '../session-manager';

// Mock Socket.IO
jest.mock('socket.io');
jest.mock('../session-manager');

describe('TmuxWebSocketServer', () => {
  let httpServer: HTTPServer;
  let mockIO: jest.Mocked<SocketIOServer>;
  let mockSocket: any;
  let mockSessionManager: jest.Mocked<TmuxSessionManager>;
  let server: TmuxWebSocketServer;

  beforeEach(() => {
    // Setup HTTP server mock
    httpServer = {} as HTTPServer;

    // Setup Socket.IO mock
    mockSocket = {
      id: 'test-socket-id',
      join: jest.fn(),
      leave: jest.fn(),
      emit: jest.fn(),
      on: jest.fn(),
    };

    mockIO = {
      on: jest.fn(),
      emit: jest.fn(),
      to: jest.fn().mockReturnValue({
        emit: jest.fn(),
      }),
      close: jest.fn(),
      sockets: {
        sockets: new Map([['socket1', {}], ['socket2', {}]]),
      },
    } as any;

    (SocketIOServer as jest.MockedClass<typeof SocketIOServer>).mockImplementation(() => mockIO);

    // Setup SessionManager mock
    mockSessionManager = {
      createSession: jest.fn(),
      destroySession: jest.fn(),
      sendCommand: jest.fn(),
      resizeSession: jest.fn(),
      listSessions: jest.fn(),
      getSession: jest.fn(),
      on: jest.fn(),
      cleanup: jest.fn(),
    } as any;

    (TmuxSessionManager as jest.MockedClass<typeof TmuxSessionManager>).mockImplementation(() => mockSessionManager);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor and Setup', () => {
    it('should initialize with default options', () => {
      server = new TmuxWebSocketServer(httpServer);

      expect(SocketIOServer).toHaveBeenCalledWith(httpServer, {
        path: '/socket.io',
        cors: {
          origin: "*",
          credentials: true
        }
      });
      expect(mockIO.on).toHaveBeenCalledWith('connection', expect.any(Function));
    });

    it('should initialize with custom options', () => {
      const options: TmuxWebSocketServerOptions = {
        port: 3001,
        path: '/custom-socket',
        cors: {
          origin: 'http://localhost:3000',
          credentials: false
        }
      };

      server = new TmuxWebSocketServer(httpServer, options);

      expect(SocketIOServer).toHaveBeenCalledWith(httpServer, {
        path: '/custom-socket',
        cors: {
          origin: 'http://localhost:3000',
          credentials: false
        }
      });
    });

    it('should set up session manager event forwarding', () => {
      server = new TmuxWebSocketServer(httpServer);

      expect(mockSessionManager.on).toHaveBeenCalledWith('session:created', expect.any(Function));
      expect(mockSessionManager.on).toHaveBeenCalledWith('session:destroyed', expect.any(Function));
      expect(mockSessionManager.on).toHaveBeenCalledWith('command:sent', expect.any(Function));
      expect(mockSessionManager.on).toHaveBeenCalledWith('activity:updated', expect.any(Function));
    });
  });

  describe('Socket Event Handlers', () => {
    let connectionHandler: Function;

    beforeEach(() => {
      server = new TmuxWebSocketServer(httpServer);
      // Get the connection handler that was registered
      connectionHandler = mockIO.on.mock.calls.find(call => call[0] === 'connection')[1];
    });

    describe('Connection Handling', () => {
      it('should handle new socket connections', () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
        
        connectionHandler(mockSocket);

        expect(consoleSpy).toHaveBeenCalledWith(`Client connected: ${mockSocket.id}`);
        expect(mockSocket.on).toHaveBeenCalledWith('create-session', expect.any(Function));
        expect(mockSocket.on).toHaveBeenCalledWith('destroy-session', expect.any(Function));
        expect(mockSocket.on).toHaveBeenCalledWith('send-command', expect.any(Function));
        expect(mockSocket.on).toHaveBeenCalledWith('resize-session', expect.any(Function));
        expect(mockSocket.on).toHaveBeenCalledWith('list-sessions', expect.any(Function));
        expect(mockSocket.on).toHaveBeenCalledWith('join-session', expect.any(Function));
        expect(mockSocket.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
        expect(mockSocket.on).toHaveBeenCalledWith('ping', expect.any(Function));

        consoleSpy.mockRestore();
      });
    });

    describe('Session Creation', () => {
      let createSessionHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        createSessionHandler = mockSocket.on.mock.calls.find(call => call[0] === 'create-session')[1];
      });

      it('should create session successfully with callback', async () => {
        const mockSession = {
          id: 'session-123',
          name: 'test-session',
          status: 'active'
        };
        mockSessionManager.createSession.mockResolvedValue(mockSession);

        const callback = jest.fn();
        const data = { name: 'test-session' };

        await createSessionHandler(data, callback);

        expect(mockSessionManager.createSession).toHaveBeenCalledWith('test-session');
        expect(mockSocket.join).toHaveBeenCalledWith('session:session-123');
        expect(callback).toHaveBeenCalledWith({ success: true, session: mockSession });
        expect(mockSocket.emit).toHaveBeenCalledWith('session-created', mockSession);
      });

      it('should handle session creation without callback', async () => {
        const mockSession = {
          id: 'session-123',
          name: 'test-session',
          status: 'active'
        };
        mockSessionManager.createSession.mockResolvedValue(mockSession);

        await createSessionHandler({ name: 'test-session' });

        expect(mockSessionManager.createSession).toHaveBeenCalledWith('test-session');
        expect(mockSocket.join).toHaveBeenCalledWith('session:session-123');
        expect(mockSocket.emit).toHaveBeenCalledWith('session-created', mockSession);
      });

      it('should handle session creation errors', async () => {
        const error = new Error('Creation failed');
        mockSessionManager.createSession.mockRejectedValue(error);

        const callback = jest.fn();
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        await createSessionHandler({ name: 'test-session' }, callback);

        expect(consoleSpy).toHaveBeenCalledWith('Error creating session:', error);
        expect(callback).toHaveBeenCalledWith({ success: false, error: 'Creation failed' });

        consoleSpy.mockRestore();
      });
    });

    describe('Session Destruction', () => {
      let destroySessionHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        destroySessionHandler = mockSocket.on.mock.calls.find(call => call[0] === 'destroy-session')[1];
      });

      it('should destroy session successfully', async () => {
        mockSessionManager.destroySession.mockResolvedValue(true);

        const callback = jest.fn();
        const sessionId = 'session-123';

        await destroySessionHandler(sessionId, callback);

        expect(mockSessionManager.destroySession).toHaveBeenCalledWith(sessionId);
        expect(mockSocket.leave).toHaveBeenCalledWith('session:session-123');
        expect(mockSocket.emit).toHaveBeenCalledWith('session-destroyed', { sessionId });
        expect(callback).toHaveBeenCalledWith({ success: true });
      });

      it('should handle failed session destruction', async () => {
        mockSessionManager.destroySession.mockResolvedValue(false);

        const callback = jest.fn();
        const sessionId = 'session-123';

        await destroySessionHandler(sessionId, callback);

        expect(mockSessionManager.destroySession).toHaveBeenCalledWith(sessionId);
        expect(mockSocket.leave).not.toHaveBeenCalled();
        expect(callback).toHaveBeenCalledWith({ success: false });
      });
    });

    describe('Command Sending', () => {
      let sendCommandHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        sendCommandHandler = mockSocket.on.mock.calls.find(call => call[0] === 'send-command')[1];
      });

      it('should send command successfully', async () => {
        mockSessionManager.sendCommand.mockResolvedValue(true);

        const callback = jest.fn();
        const data = { sessionId: 'session-123', command: 'ls -la' };

        await sendCommandHandler(data, callback);

        expect(mockSessionManager.sendCommand).toHaveBeenCalledWith('session-123', 'ls -la');
        expect(mockIO.to).toHaveBeenCalledWith('session:session-123');
        expect(callback).toHaveBeenCalledWith({ success: true });
      });

      it('should handle failed command sending', async () => {
        mockSessionManager.sendCommand.mockResolvedValue(false);

        const callback = jest.fn();
        const data = { sessionId: 'session-123', command: 'ls -la' };

        await sendCommandHandler(data, callback);

        expect(mockSessionManager.sendCommand).toHaveBeenCalledWith('session-123', 'ls -la');
        expect(callback).toHaveBeenCalledWith({ success: false });
      });
    });

    describe('Session Resize', () => {
      let resizeSessionHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        resizeSessionHandler = mockSocket.on.mock.calls.find(call => call[0] === 'resize-session')[1];
      });

      it('should resize session successfully', async () => {
        mockSessionManager.resizeSession.mockResolvedValue(true);

        const callback = jest.fn();
        const data = { sessionId: 'session-123', width: 80, height: 24 };

        await resizeSessionHandler(data, callback);

        expect(mockSessionManager.resizeSession).toHaveBeenCalledWith('session-123', 80, 24);
        expect(callback).toHaveBeenCalledWith({ success: true });
      });
    });

    describe('Session Listing', () => {
      let listSessionsHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        listSessionsHandler = mockSocket.on.mock.calls.find(call => call[0] === 'list-sessions')[1];
      });

      it('should list sessions successfully', () => {
        const mockSessions = [{ id: 'session-1' }, { id: 'session-2' }];
        mockSessionManager.listSessions.mockReturnValue(mockSessions);

        const callback = jest.fn();

        listSessionsHandler(callback);

        expect(mockSessionManager.listSessions).toHaveBeenCalled();
        expect(callback).toHaveBeenCalledWith({ success: true, sessions: mockSessions });
      });
    });

    describe('Session Joining', () => {
      let joinSessionHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        joinSessionHandler = mockSocket.on.mock.calls.find(call => call[0] === 'join-session')[1];
      });

      it('should join existing session', () => {
        const mockSession = { id: 'session-123', name: 'test' };
        mockSessionManager.getSession.mockReturnValue(mockSession);

        const callback = jest.fn();
        const sessionId = 'session-123';

        joinSessionHandler(sessionId, callback);

        expect(mockSessionManager.getSession).toHaveBeenCalledWith(sessionId);
        expect(mockSocket.join).toHaveBeenCalledWith('session:session-123');
        expect(callback).toHaveBeenCalledWith({ success: true, session: mockSession });
      });

      it('should handle joining non-existent session', () => {
        mockSessionManager.getSession.mockReturnValue(null);

        const callback = jest.fn();
        const sessionId = 'non-existent';

        joinSessionHandler(sessionId, callback);

        expect(mockSessionManager.getSession).toHaveBeenCalledWith(sessionId);
        expect(mockSocket.join).not.toHaveBeenCalled();
        expect(callback).toHaveBeenCalledWith({ success: false, error: 'Session not found' });
      });
    });

    describe('Disconnect Handling', () => {
      let disconnectHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        disconnectHandler = mockSocket.on.mock.calls.find(call => call[0] === 'disconnect')[1];
      });

      it('should handle socket disconnection', () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
        
        // Simulate active session
        server['activeSessions'].set(mockSocket.id, 'session-123');

        disconnectHandler();

        expect(consoleSpy).toHaveBeenCalledWith(`Client disconnected: ${mockSocket.id}`);
        expect(mockSocket.leave).toHaveBeenCalledWith('session:session-123');
        expect(server['activeSessions'].has(mockSocket.id)).toBe(false);

        consoleSpy.mockRestore();
      });

      it('should handle disconnection without active session', () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
        
        disconnectHandler();

        expect(consoleSpy).toHaveBeenCalledWith(`Client disconnected: ${mockSocket.id}`);
        expect(mockSocket.leave).not.toHaveBeenCalled();

        consoleSpy.mockRestore();
      });
    });

    describe('Ping Handling', () => {
      let pingHandler: Function;

      beforeEach(() => {
        connectionHandler(mockSocket);
        pingHandler = mockSocket.on.mock.calls.find(call => call[0] === 'ping')[1];
      });

      it('should respond to ping with pong', () => {
        const callback = jest.fn();

        pingHandler(callback);

        expect(callback).toHaveBeenCalledWith({
          pong: true,
          timestamp: expect.any(Number)
        });
      });

      it('should handle ping without callback', () => {
        expect(() => pingHandler()).not.toThrow();
      });
    });
  });

  describe('Public Methods', () => {
    beforeEach(() => {
      server = new TmuxWebSocketServer(httpServer);
    });

    it('should get connected clients count', () => {
      const count = server.getConnectedClientsCount();
      expect(count).toBe(2);
    });

    it('should get active sessions count', () => {
      const mockSessions = [{ id: '1' }, { id: '2' }, { id: '3' }];
      mockSessionManager.listSessions.mockReturnValue(mockSessions);

      const count = server.getActiveSessionsCount();
      expect(count).toBe(3);
    });

    it('should broadcast message to all clients', () => {
      const event = 'test-event';
      const data = { message: 'test' };

      server.broadcast(event, data);

      expect(mockIO.emit).toHaveBeenCalledWith(event, data);
    });

    it('should send message to specific session', () => {
      const sessionId = 'session-123';
      const event = 'test-event';
      const data = { message: 'test' };

      server.sendToSession(sessionId, event, data);

      expect(mockIO.to).toHaveBeenCalledWith('session:session-123');
    });

    it('should close server and cleanup', () => {
      server.close();

      expect(mockSessionManager.cleanup).toHaveBeenCalled();
      expect(mockIO.close).toHaveBeenCalled();
    });
  });

  describe('Session Manager Event Forwarding', () => {
    beforeEach(() => {
      server = new TmuxWebSocketServer(httpServer);
    });

    it('should forward session created events', () => {
      const session = { id: 'session-123', name: 'test' };
      const sessionCreatedHandler = mockSessionManager.on.mock.calls.find(call => call[0] === 'session:created')[1];

      sessionCreatedHandler(session);

      expect(mockIO.emit).toHaveBeenCalledWith('session-created', session);
    });

    it('should forward session destroyed events', () => {
      const session = { id: 'session-123', name: 'test' };
      const sessionDestroyedHandler = mockSessionManager.on.mock.calls.find(call => call[0] === 'session:destroyed')[1];

      sessionDestroyedHandler(session);

      expect(mockIO.emit).toHaveBeenCalledWith('session-destroyed', { sessionId: 'session-123' });
    });

    it('should forward command sent events', () => {
      const data = { sessionId: 'session-123', command: 'ls' };
      const commandSentHandler = mockSessionManager.on.mock.calls.find(call => call[0] === 'command:sent')[1];

      commandSentHandler(data);

      expect(mockIO.to).toHaveBeenCalledWith('session:session-123');
    });

    it('should forward activity updated events', () => {
      const data = { sessionId: 'session-123', timestamp: new Date() };
      const activityUpdatedHandler = mockSessionManager.on.mock.calls.find(call => call[0] === 'activity:updated')[1];

      activityUpdatedHandler(data);

      expect(mockIO.to).toHaveBeenCalledWith('session:session-123');
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      server = new TmuxWebSocketServer(httpServer);
    });

    it('should handle errors in event handlers gracefully', async () => {
      const connectionHandler = mockIO.on.mock.calls.find(call => call[0] === 'connection')[1];
      connectionHandler(mockSocket);

      const createSessionHandler = mockSocket.on.mock.calls.find(call => call[0] === 'create-session')[1];
      
      const error = new Error('Session creation failed');
      mockSessionManager.createSession.mockRejectedValue(error);

      const callback = jest.fn();
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      await createSessionHandler({ name: 'test' }, callback);

      expect(consoleSpy).toHaveBeenCalledWith('Error creating session:', error);
      expect(callback).toHaveBeenCalledWith({ success: false, error: 'Session creation failed' });

      consoleSpy.mockRestore();
    });
  });
});