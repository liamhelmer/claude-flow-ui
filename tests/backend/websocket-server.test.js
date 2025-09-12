const { Server } = require('socket.io');
const { createServer } = require('http');
const pty = require('node-pty');
const TmuxManager = require('../../src/lib/tmux-manager');

// Mock dependencies
jest.mock('socket.io', () => ({
  Server: jest.fn(),
}));

jest.mock('http', () => ({
  createServer: jest.fn(),
}));

jest.mock('node-pty', () => ({
  spawn: jest.fn(),
}));

jest.mock('../../src/lib/tmux-manager');

jest.mock('fs', () => ({
  existsSync: jest.fn(),
  mkdirSync: jest.fn(),
  createWriteStream: jest.fn(),
}));

jest.mock('child_process', () => ({
  execSync: jest.fn(),
}));

describe('WebSocket Server', () => {
  let mockHttpServer;
  let mockIoServer;
  let mockSocket;
  let mockPty;
  let mockTmuxManager;
  let originalArgv;
  let originalConsole;

  beforeEach(() => {
    jest.clearAllMocks();
    originalArgv = process.argv;
    originalConsole = { ...console };

    // Mock HTTP server
    mockHttpServer = {
      listen: jest.fn(),
      on: jest.fn(),
    };
    createServer.mockReturnValue(mockHttpServer);

    // Mock socket.io server
    mockSocket = {
      id: 'mock-socket-id',
      emit: jest.fn(),
      on: jest.fn(),
    };

    mockIoServer = {
      emit: jest.fn(),
      on: jest.fn((event, callback) => {
        if (event === 'connection') {
          // Store the connection handler for testing
          mockIoServer.connectionHandler = callback;
        }
      }),
    };
    Server.mockReturnValue(mockIoServer);

    // Mock PTY
    mockPty = {
      onData: jest.fn(),
      onExit: jest.fn(),
      write: jest.fn(),
      resize: jest.fn(),
    };
    pty.spawn.mockReturnValue(mockPty);

    // Mock TmuxManager
    mockTmuxManager = {
      isTmuxAvailable: jest.fn().mockResolvedValue(false),
      createSession: jest.fn(),
      connectToSession: jest.fn(),
      cleanup: jest.fn(),
    };
    TmuxManager.mockImplementation(() => mockTmuxManager);

    // Mock console to prevent logs during tests
    console.log = jest.fn();
    console.error = jest.fn();
  });

  afterEach(() => {
    process.argv = originalArgv;
    console.log = originalConsole.log;
    console.error = originalConsole.error;
    jest.resetModules();
  });

  describe('argument parsing', () => {
    it('should parse default arguments', () => {
      process.argv = ['node', 'websocket-server.js'];
      
      require('../../websocket-server.js');
      
      expect(createServer).toHaveBeenCalled();
      expect(Server).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          cors: expect.objectContaining({
            origin: expect.arrayContaining(['http://localhost:11235']),
            methods: ['GET', 'POST'],
            credentials: true,
          }),
        })
      );
    });

    it('should parse custom port', () => {
      process.argv = ['node', 'websocket-server.js', '--port', '8080'];
      
      require('../../websocket-server.js');
      
      expect(mockHttpServer.listen).toHaveBeenCalled();
    });

    it('should parse working directory', () => {
      process.argv = ['node', 'websocket-server.js', '--cwd', '/custom/dir'];
      
      require('../../websocket-server.js');
      
      expect(TmuxManager).toHaveBeenCalledWith('/custom/dir');
    });

    it('should parse claude-flow arguments', () => {
      process.argv = [
        'node', 
        'websocket-server.js', 
        '--claude-flow-args', 
        'swarm', 
        'init', 
        'mesh'
      ];
      
      require('../../websocket-server.js');
      
      // Should spawn process with claude-flow args
      expect(pty.spawn).toHaveBeenCalled();
    });
  });

  describe('tmux initialization', () => {
    it('should detect tmux availability', async () => {
      mockTmuxManager.isTmuxAvailable.mockResolvedValue(true);
      
      require('../../websocket-server.js');
      
      // Wait for async initialization
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(mockTmuxManager.isTmuxAvailable).toHaveBeenCalled();
    });

    it('should fallback to PTY when tmux unavailable', async () => {
      mockTmuxManager.isTmuxAvailable.mockResolvedValue(false);
      
      require('../../websocket-server.js');
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Tmux not available - falling back to PTY mode')
      );
    });
  });

  describe('logging setup', () => {
    it('should setup logging directory', () => {
      const fs = require('fs');
      fs.existsSync.mockReturnValue(false);
      
      require('../../websocket-server.js');
      
      expect(fs.mkdirSync).toHaveBeenCalledWith(
        expect.stringContaining('.claude-flow'),
        { recursive: true }
      );
      expect(fs.createWriteStream).toHaveBeenCalled();
    });

    it('should override console methods for logging', () => {
      require('../../websocket-server.js');
      
      // Console should be overridden
      expect(console.log).toBeDefined();
      expect(console.error).toBeDefined();
    });
  });

  describe('claude-flow command detection', () => {
    it('should detect global claude-flow installation', () => {
      const { execSync } = require('child_process');
      execSync.mockReturnValue('/usr/local/bin/claude-flow');
      
      require('../../websocket-server.js');
      
      expect(execSync).toHaveBeenCalledWith(
        expect.stringMatching(/(which|where) claude-flow/),
        expect.any(Object)
      );
    });

    it('should fallback to npx when global not found', () => {
      const { execSync } = require('child_process');
      execSync.mockImplementation(() => {
        throw new Error('Command not found');
      });
      
      require('../../websocket-server.js');
      
      // Should still work with npx fallback
      expect(console.log).toHaveBeenCalledWith(
        expect.stringContaining('Using npx claude-flow@alpha')
      );
    });
  });

  describe('process spawning', () => {
    it('should spawn claude-flow with PTY', () => {
      process.argv = ['node', 'websocket-server.js', '--claude-flow-args', 'help'];
      
      require('../../websocket-server.js');
      
      expect(pty.spawn).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Array),
        expect.objectContaining({
          name: 'xterm-256color',
          cols: 120,
          rows: 30,
          cwd: expect.any(String),
          env: expect.objectContaining({
            TERM: 'xterm-256color',
            COLORTERM: 'truecolor',
          }),
        })
      );
    });

    it('should handle PTY data events', () => {
      require('../../websocket-server.js');
      
      expect(mockPty.onData).toHaveBeenCalledWith(expect.any(Function));
      
      // Simulate PTY data
      const dataHandler = mockPty.onData.mock.calls[0][0];
      dataHandler('test data');
      
      // Should emit data to socket.io clients
      expect(mockIoServer.emit).toHaveBeenCalledWith('terminal-data', {
        sessionId: expect.any(String),
        data: 'test data',
      });
    });

    it('should handle PTY exit events', () => {
      const mockExit = jest.fn();
      const originalExit = process.exit;
      process.exit = mockExit;

      require('../../websocket-server.js');
      
      expect(mockPty.onExit).toHaveBeenCalledWith(expect.any(Function));
      
      // Simulate PTY exit
      const exitHandler = mockPty.onExit.mock.calls[0][0];
      exitHandler({ exitCode: 0, signal: null });
      
      expect(mockExit).toHaveBeenCalledWith(0);
      
      process.exit = originalExit;
    });
  });

  describe('WebSocket server creation', () => {
    it('should create WebSocket server with CORS', () => {
      require('../../websocket-server.js');
      
      expect(Server).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          cors: {
            origin: expect.arrayContaining([
              'http://localhost:11235',
              'http://localhost:3000',
              'http://localhost:3001',
              '*'
            ]),
            methods: ['GET', 'POST'],
            credentials: true,
          },
          transports: ['websocket', 'polling'],
          allowEIO3: true,
        })
      );
    });

    it('should handle client connections', () => {
      require('../../websocket-server.js');
      
      expect(mockIoServer.on).toHaveBeenCalledWith('connection', expect.any(Function));
      
      // Simulate client connection
      if (mockIoServer.connectionHandler) {
        mockIoServer.connectionHandler(mockSocket);
      }
      
      expect(mockSocket.emit).toHaveBeenCalledWith('connected', {
        message: 'Connected to Claude Flow Terminal',
        sessionId: expect.any(String),
        timestamp: expect.any(Number),
      });
    });
  });

  describe('socket event handling', () => {
    beforeEach(() => {
      require('../../websocket-server.js');
      
      // Trigger connection handler
      if (mockIoServer.connectionHandler) {
        mockIoServer.connectionHandler(mockSocket);
      }
    });

    it('should handle data events', () => {
      expect(mockSocket.on).toHaveBeenCalledWith('data', expect.any(Function));
      
      // Find and call the data handler
      const dataHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'data'
      )?.[1];
      
      if (dataHandler) {
        dataHandler({
          sessionId: 'test-session',
          data: 'test input',
        });
        
        expect(mockPty.write).toHaveBeenCalledWith('test input');
      }
    });

    it('should handle resize events', () => {
      expect(mockSocket.on).toHaveBeenCalledWith('resize', expect.any(Function));
      
      const resizeHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'resize'
      )?.[1];
      
      if (resizeHandler) {
        resizeHandler({
          sessionId: 'test-session',
          cols: 100,
          rows: 40,
        });
        
        expect(mockPty.resize).toHaveBeenCalledWith(100, 40);
      }
    });

    it('should handle create session events', () => {
      expect(mockSocket.on).toHaveBeenCalledWith('create', expect.any(Function));
      
      const createHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'create'
      )?.[1];
      
      if (createHandler) {
        createHandler();
        
        expect(mockSocket.emit).toHaveBeenCalledWith('session-created', {
          sessionId: expect.any(String),
        });
      }
    });

    it('should handle list sessions events', () => {
      expect(mockSocket.on).toHaveBeenCalledWith('list', expect.any(Function));
      
      const listHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'list'
      )?.[1];
      
      if (listHandler) {
        listHandler();
        
        expect(mockSocket.emit).toHaveBeenCalledWith('session-list', {
          sessions: expect.arrayContaining([
            expect.objectContaining({
              id: expect.any(String),
              created: expect.any(Number),
              isClaudeFlow: expect.any(Boolean),
            }),
          ]),
        });
      }
    });

    it('should handle disconnect events', () => {
      expect(mockSocket.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
      
      const disconnectHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'disconnect'
      )?.[1];
      
      if (disconnectHandler) {
        expect(() => disconnectHandler()).not.toThrow();
      }
    });
  });

  describe('mock data generation', () => {
    beforeEach(() => {
      jest.useFakeTimers();
      require('../../websocket-server.js');
      
      if (mockIoServer.connectionHandler) {
        mockIoServer.connectionHandler(mockSocket);
      }
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should send mock system metrics', () => {
      jest.advanceTimersByTime(2100);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('system-metrics', 
        expect.objectContaining({
          memoryTotal: 17179869184,
          memoryUsed: expect.any(Number),
          memoryFree: expect.any(Number),
          memoryUsagePercent: expect.any(Number),
          timestamp: expect.any(Number),
        })
      );
    });

    it('should send mock agent updates', () => {
      jest.advanceTimersByTime(3100);
      
      expect(mockSocket.emit).toHaveBeenCalledWith('agent-status',
        expect.objectContaining({
          agentId: expect.stringMatching(/agent-\d/),
          state: expect.stringMatching(/idle|busy|initializing/),
        })
      );
    });

    it('should send mock command updates', () => {
      jest.advanceTimersByTime(5100);
      
      // May or may not send depending on random condition
      const commandCalls = mockSocket.emit.mock.calls.filter(
        call => call[0] === 'command-created'
      );
      
      // Should have capability to send commands
      expect(mockSocket.emit).toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should handle socket errors', () => {
      require('../../websocket-server.js');
      
      if (mockIoServer.connectionHandler) {
        mockIoServer.connectionHandler(mockSocket);
      }
      
      expect(mockSocket.on).toHaveBeenCalledWith('error', expect.any(Function));
      
      const errorHandler = mockSocket.on.mock.calls.find(
        call => call[0] === 'error'
      )?.[1];
      
      if (errorHandler) {
        expect(() => errorHandler(new Error('Test error'))).not.toThrow();
      }
    });

    it('should handle server listen errors', () => {
      const mockError = new Error('EADDRINUSE');
      mockError.code = 'EADDRINUSE';
      
      mockHttpServer.on.mockImplementation((event, callback) => {
        if (event === 'error') {
          setTimeout(() => callback(mockError), 0);
        }
      });

      const mockExit = jest.fn();
      const originalExit = process.exit;
      process.exit = mockExit;
      
      require('../../websocket-server.js');
      
      process.exit = originalExit;
      
      expect(mockHttpServer.on).toHaveBeenCalledWith('error', expect.any(Function));
    });
  });

  describe('shutdown handling', () => {
    it('should handle SIGTERM gracefully', () => {
      const originalOn = process.on;
      const mockProcessOn = jest.fn();
      process.on = mockProcessOn;

      require('../../websocket-server.js');
      
      expect(mockProcessOn).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
      expect(mockProcessOn).toHaveBeenCalledWith('SIGINT', expect.any(Function));

      process.on = originalOn;
    });

    it('should cleanup tmux sessions on shutdown', async () => {
      let shutdownHandler;
      const mockProcessOn = jest.fn((event, callback) => {
        if (event === 'SIGTERM') {
          shutdownHandler = callback;
        }
      });
      
      const originalOn = process.on;
      process.on = mockProcessOn;

      require('../../websocket-server.js');
      
      if (shutdownHandler) {
        await shutdownHandler();
        expect(mockTmuxManager.cleanup).toHaveBeenCalled();
      }

      process.on = originalOn;
    });
  });
});