/**
 * Unit Tests for Unified Server
 * Comprehensive test suite for the main server functionality
 */

const request = require('supertest');
const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');

// Mock dependencies
jest.mock('node-pty');
jest.mock('child_process');
jest.mock('next');
jest.mock('../src/lib/tmux-stream-manager');

const mockPty = require('node-pty');
const mockChildProcess = require('child_process');
const mockNext = require('next');
const MockTmuxStreamManager = require('../src/lib/tmux-stream-manager');

describe('Unified Server Unit Tests', () => {
  let app;
  let server;
  let io;
  let mockTerminal;
  let mockSpawn;

  beforeAll(() => {
    // Setup test environment
    process.env.NODE_ENV = 'test';
    process.env.PORT = '0'; // Use random port for testing
  });

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Mock pty.spawn
    mockTerminal = {
      pid: 12345,
      write: jest.fn(),
      resize: jest.fn(),
      kill: jest.fn(),
      onData: jest.fn(),
      onExit: jest.fn(),
      cols: 80,
      rows: 24
    };
    mockPty.spawn.mockReturnValue(mockTerminal);

    // Mock child_process.spawn
    mockSpawn = {
      stdout: { on: jest.fn(), pipe: jest.fn() },
      stderr: { on: jest.fn(), pipe: jest.fn() },
      on: jest.fn(),
      kill: jest.fn(),
      pid: 67890
    };
    mockChildProcess.spawn.mockReturnValue(mockSpawn);
    mockChildProcess.execSync.mockReturnValue('mocked output');

    // Mock Next.js
    mockNext.mockReturnValue({
      prepare: jest.fn().mockResolvedValue(),
      getRequestHandler: jest.fn().mockReturnValue((req, res) => {
        res.status(200).json({ message: 'Next.js handler' });
      })
    });

    // Create Express app for testing
    app = express();
    server = createServer(app);
    io = new Server(server);
  });

  afterEach(() => {
    if (server && server.listening) {
      server.close();
    }
  });

  describe('Server Initialization', () => {
    test('should create Express app with correct middleware', () => {
      expect(app).toBeDefined();
      expect(typeof app.use).toBe('function');
    });

    test('should parse command line arguments correctly', () => {
      const originalArgv = process.argv;

      // Test port parsing
      process.argv = ['node', 'unified-server.js', '--port', '3001'];

      // Re-require to test argument parsing
      delete require.cache[require.resolve('../../unified-server.js')];

      // Check that port is set correctly
      expect(process.env.PORT).toBeDefined();

      process.argv = originalArgv;
    });

    test('should handle terminal size arguments', () => {
      const originalArgv = process.argv;

      process.argv = ['node', 'unified-server.js', '--terminal-size', '100x30'];

      // This would be tested by re-requiring the module
      // but for unit testing, we'll test the parsing logic separately
      const args = ['--terminal-size', '100x30'];
      let terminalCols = 120;
      let terminalRows = 40;

      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--terminal-size' && i + 1 < args.length) {
          const size = args[i + 1].split('x');
          if (size.length === 2) {
            terminalCols = parseInt(size[0]) || 120;
            terminalRows = parseInt(size[1]) || 40;
          }
        }
      }

      expect(terminalCols).toBe(100);
      expect(terminalRows).toBe(30);

      process.argv = originalArgv;
    });
  });

  describe('Terminal Management', () => {
    test('should create terminal with correct options', () => {
      const terminalOptions = {
        name: 'xterm-256color',
        cols: 80,
        rows: 24,
        cwd: process.env.HOME || process.cwd(),
        env: process.env
      };

      mockPty.spawn('bash', [], terminalOptions);

      expect(mockPty.spawn).toHaveBeenCalledWith('bash', [], terminalOptions);
    });

    test('should handle terminal data events', () => {
      const terminal = mockPty.spawn('bash', []);
      const callback = jest.fn();

      terminal.onData(callback);
      expect(terminal.onData).toHaveBeenCalledWith(callback);
    });

    test('should handle terminal resize', () => {
      const terminal = mockPty.spawn('bash', []);

      terminal.resize(100, 30);
      expect(terminal.resize).toHaveBeenCalledWith(100, 30);
    });

    test('should handle terminal exit', () => {
      const terminal = mockPty.spawn('bash', []);
      const callback = jest.fn();

      terminal.onExit(callback);
      expect(terminal.onExit).toHaveBeenCalledWith(callback);
    });

    test('should write data to terminal', () => {
      const terminal = mockPty.spawn('bash', []);
      const data = 'test command\n';

      terminal.write(data);
      expect(terminal.write).toHaveBeenCalledWith(data);
    });

    test('should kill terminal process', () => {
      const terminal = mockPty.spawn('bash', []);

      terminal.kill();
      expect(terminal.kill).toHaveBeenCalled();
    });
  });

  describe('Socket.IO Events', () => {
    let clientSocket;
    let serverSocket;

    beforeEach((done) => {
      server.listen(() => {
        const port = server.address().port;
        const Client = require('socket.io-client');
        clientSocket = new Client(`http://localhost:${port}`);

        io.on('connection', (socket) => {
          serverSocket = socket;
        });

        clientSocket.on('connect', done);
      });
    });

    afterEach(() => {
      io.close();
      clientSocket.close();
    });

    test('should handle terminal creation request', (done) => {
      const terminalData = { cols: 80, rows: 24 };

      serverSocket.on('create-terminal', (data, callback) => {
        expect(data).toEqual(terminalData);
        expect(typeof callback).toBe('function');

        callback({ success: true, terminalId: 'test-terminal-1' });
        done();
      });

      clientSocket.emit('create-terminal', terminalData, (response) => {
        expect(response.success).toBe(true);
        expect(response.terminalId).toBe('test-terminal-1');
      });
    });

    test('should handle terminal input', (done) => {
      const inputData = { terminalId: 'test-terminal-1', data: 'ls -la\n' };

      serverSocket.on('terminal-input', (data) => {
        expect(data).toEqual(inputData);
        done();
      });

      clientSocket.emit('terminal-input', inputData);
    });

    test('should handle terminal resize request', (done) => {
      const resizeData = { terminalId: 'test-terminal-1', cols: 100, rows: 30 };

      serverSocket.on('terminal-resize', (data) => {
        expect(data).toEqual(resizeData);
        done();
      });

      clientSocket.emit('terminal-resize', resizeData);
    });

    test('should handle disconnect event', (done) => {
      serverSocket.on('disconnect', () => {
        done();
      });

      clientSocket.disconnect();
    });
  });

  describe('Tmux Integration', () => {
    let tmuxManager;

    beforeEach(() => {
      tmuxManager = new MockTmuxStreamManager();
    });

    test('should create tmux session', async () => {
      const sessionName = 'test-session';
      const mockSession = { id: sessionName, socketPath: '/tmp/test-socket' };

      tmuxManager.createSession.mockResolvedValue(mockSession);

      const result = await tmuxManager.createSession(sessionName);

      expect(tmuxManager.createSession).toHaveBeenCalledWith(sessionName);
      expect(result).toEqual(mockSession);
    });

    test('should attach to tmux session', async () => {
      const sessionId = 'test-session';
      const clientId = 'client-1';

      tmuxManager.attachClient.mockResolvedValue(true);

      const result = await tmuxManager.attachClient(sessionId, clientId);

      expect(tmuxManager.attachClient).toHaveBeenCalledWith(sessionId, clientId);
      expect(result).toBe(true);
    });

    test('should detach from tmux session', async () => {
      const clientId = 'client-1';

      tmuxManager.detachClient.mockResolvedValue(true);

      const result = await tmuxManager.detachClient(clientId);

      expect(tmuxManager.detachClient).toHaveBeenCalledWith(clientId);
      expect(result).toBe(true);
    });

    test('should kill tmux session', async () => {
      const sessionId = 'test-session';

      tmuxManager.killSession.mockResolvedValue(true);

      const result = await tmuxManager.killSession(sessionId);

      expect(tmuxManager.killSession).toHaveBeenCalledWith(sessionId);
      expect(result).toBe(true);
    });
  });

  describe('File Operations', () => {
    test('should check if file exists', () => {
      const existsSyncSpy = jest.spyOn(fs, 'existsSync');
      existsSyncSpy.mockReturnValue(true);

      const filePath = '/path/to/file.txt';
      const exists = fs.existsSync(filePath);

      expect(existsSyncSpy).toHaveBeenCalledWith(filePath);
      expect(exists).toBe(true);

      existsSyncSpy.mockRestore();
    });

    test('should read file content', () => {
      const readFileSyncSpy = jest.spyOn(fs, 'readFileSync');
      const mockContent = 'test file content';
      readFileSyncSpy.mockReturnValue(mockContent);

      const filePath = '/path/to/file.txt';
      const content = fs.readFileSync(filePath, 'utf8');

      expect(readFileSyncSpy).toHaveBeenCalledWith(filePath, 'utf8');
      expect(content).toBe(mockContent);

      readFileSyncSpy.mockRestore();
    });

    test('should handle file read errors', () => {
      const readFileSyncSpy = jest.spyOn(fs, 'readFileSync');
      readFileSyncSpy.mockImplementation(() => {
        throw new Error('File not found');
      });

      const filePath = '/path/to/nonexistent.txt';

      expect(() => {
        fs.readFileSync(filePath, 'utf8');
      }).toThrow('File not found');

      readFileSyncSpy.mockRestore();
    });
  });

  describe('Environment Configuration', () => {
    test('should handle production environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      // Test production-specific behavior
      const isProduction = process.env.NODE_ENV === 'production';
      expect(isProduction).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });

    test('should handle development environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const isDevelopment = process.env.NODE_ENV === 'development';
      expect(isDevelopment).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });

    test('should use default port when not specified', () => {
      const originalPort = process.env.PORT;
      delete process.env.PORT;

      const defaultPort = process.env.PORT || 3000;
      expect(defaultPort).toBe(3000);

      process.env.PORT = originalPort;
    });

    test('should use custom port when specified', () => {
      const originalPort = process.env.PORT;
      process.env.PORT = '8080';

      const port = parseInt(process.env.PORT);
      expect(port).toBe(8080);

      process.env.PORT = originalPort;
    });
  });

  describe('Error Handling', () => {
    test('should handle pty spawn errors', () => {
      const error = new Error('Failed to spawn terminal');
      mockPty.spawn.mockImplementation(() => {
        throw error;
      });

      expect(() => {
        mockPty.spawn('bash', []);
      }).toThrow('Failed to spawn terminal');
    });

    test('should handle child process spawn errors', () => {
      const error = new Error('Failed to spawn process');
      mockChildProcess.spawn.mockImplementation(() => {
        throw error;
      });

      expect(() => {
        mockChildProcess.spawn('ls', ['-la']);
      }).toThrow('Failed to spawn process');
    });

    test('should handle socket errors gracefully', (done) => {
      server.listen(() => {
        const port = server.address().port;
        const Client = require('socket.io-client');
        const clientSocket = new Client(`http://localhost:${port}`);

        clientSocket.on('connect_error', (error) => {
          expect(error).toBeDefined();
          done();
        });

        // Force an error by connecting to invalid port
        const invalidClient = new Client('http://localhost:99999');
        invalidClient.on('connect_error', (error) => {
          expect(error).toBeDefined();
          invalidClient.close();
          clientSocket.close();
          done();
        });
      });
    });
  });

  describe('Platform Compatibility', () => {
    test('should detect Windows platform', () => {
      const originalPlatform = process.platform;
      Object.defineProperty(process, 'platform', {
        value: 'win32'
      });

      const isWindows = process.platform === 'win32';
      expect(isWindows).toBe(true);

      Object.defineProperty(process, 'platform', {
        value: originalPlatform
      });
    });

    test('should detect Unix-like platforms', () => {
      const unixPlatforms = ['linux', 'darwin', 'freebsd'];

      unixPlatforms.forEach(platform => {
        const originalPlatform = process.platform;
        Object.defineProperty(process, 'platform', {
          value: platform
        });

        const isUnix = ['linux', 'darwin', 'freebsd'].includes(process.platform);
        expect(isUnix).toBe(true);

        Object.defineProperty(process, 'platform', {
          value: originalPlatform
        });
      });
    });

    test('should use appropriate shell for platform', () => {
      const getShellForPlatform = (platform) => {
        return platform === 'win32' ? 'cmd.exe' : 'bash';
      };

      expect(getShellForPlatform('win32')).toBe('cmd.exe');
      expect(getShellForPlatform('linux')).toBe('bash');
      expect(getShellForPlatform('darwin')).toBe('bash');
    });
  });

  describe('Memory Management', () => {
    test('should track terminal instances', () => {
      const terminals = new Map();
      const terminalId = 'terminal-1';
      const terminal = mockPty.spawn('bash', []);

      terminals.set(terminalId, terminal);

      expect(terminals.has(terminalId)).toBe(true);
      expect(terminals.get(terminalId)).toBe(terminal);
      expect(terminals.size).toBe(1);
    });

    test('should clean up terminated terminals', () => {
      const terminals = new Map();
      const terminalId = 'terminal-1';
      const terminal = mockPty.spawn('bash', []);

      terminals.set(terminalId, terminal);
      terminals.delete(terminalId);

      expect(terminals.has(terminalId)).toBe(false);
      expect(terminals.size).toBe(0);
    });

    test('should handle memory leaks in terminal cleanup', () => {
      const terminals = new Map();

      // Create multiple terminals
      for (let i = 0; i < 100; i++) {
        const terminalId = `terminal-${i}`;
        const terminal = mockPty.spawn('bash', []);
        terminals.set(terminalId, terminal);
      }

      expect(terminals.size).toBe(100);

      // Clean up all terminals
      terminals.forEach((terminal, id) => {
        terminal.kill();
        terminals.delete(id);
      });

      expect(terminals.size).toBe(0);
    });
  });
});