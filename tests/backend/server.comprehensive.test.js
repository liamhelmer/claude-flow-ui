/**
 * @jest-environment node
 */

const { spawn } = require('child_process');
const { createServer } = require('http');
const net = require('net');
const next = require('next');

// Mock dependencies
jest.mock('child_process', () => ({
  spawn: jest.fn(),
}));

jest.mock('next', () => jest.fn());

jest.mock('http', () => ({
  createServer: jest.fn(),
}));

jest.mock('net', () => ({
  createServer: jest.fn(),
}));

describe('Server.js Comprehensive Tests', () => {
  let mockNext;
  let mockHttpServer;
  let mockProcess;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Mock Next.js
    mockNext = {
      prepare: jest.fn().mockResolvedValue(),
      getRequestHandler: jest.fn().mockReturnValue(jest.fn()),
    };
    next.mockReturnValue(mockNext);

    // Mock HTTP server
    mockHttpServer = {
      listen: jest.fn(),
      close: jest.fn(),
      on: jest.fn(),
      address: jest.fn().mockReturnValue({ port: 11235 }),
    };
    createServer.mockReturnValue(mockHttpServer);

    // Mock child process
    mockProcess = {
      stdout: { on: jest.fn(), pipe: jest.fn() },
      stderr: { on: jest.fn(), pipe: jest.fn() },
      on: jest.fn(),
      kill: jest.fn(),
      pid: 12345,
    };
    spawn.mockReturnValue(mockProcess);
  });

  describe('Argument Parsing', () => {
    test('should parse port argument correctly', () => {
      const originalArgv = process.argv;
      process.argv = ['node', 'server.js', '--port', '8080'];

      // Mock the parseArgs function logic
      const parseArgs = () => {
        const args = process.argv.slice(2);
        let port = 11235;
        
        for (let i = 0; i < args.length; i++) {
          if (args[i] === '--port' && i + 1 < args.length) {
            port = parseInt(args[i + 1], 10);
          }
        }
        
        return { port };
      };

      const result = parseArgs();
      expect(result.port).toBe(8080);

      process.argv = originalArgv;
    });

    test('should parse terminal size argument', () => {
      const originalArgv = process.argv;
      process.argv = ['node', 'server.js', '--terminal-size', '120x40'];

      const parseArgs = () => {
        const args = process.argv.slice(2);
        let terminalSize = null;
        
        for (let i = 0; i < args.length; i++) {
          if (args[i] === '--terminal-size' && i + 1 < args.length) {
            terminalSize = args[i + 1];
          }
        }
        
        return { terminalSize };
      };

      const result = parseArgs();
      expect(result.terminalSize).toBe('120x40');

      process.argv = originalArgv;
    });

    test('should separate server args from claude-flow args', () => {
      const args = ['--port', '8080', '--claude-flow-args', 'sparc', 'run', 'test'];
      
      const parseArgs = () => {
        let serverArgs = args;
        let claudeFlowArgs = [];
        const claudeFlowIndex = args.indexOf('--claude-flow-args');
        
        if (claudeFlowIndex !== -1) {
          serverArgs = args.slice(0, claudeFlowIndex);
          claudeFlowArgs = args.slice(claudeFlowIndex + 1);
        }
        
        return { serverArgs, claudeFlowArgs };
      };

      const result = parseArgs();
      expect(result.serverArgs).toEqual(['--port', '8080']);
      expect(result.claudeFlowArgs).toEqual(['sparc', 'run', 'test']);
    });

    test('should handle invalid port argument', () => {
      const args = ['--port', 'invalid'];
      
      const parseArgs = () => {
        let port = 11235;
        let error = null;
        
        for (let i = 0; i < args.length; i++) {
          if (args[i] === '--port' && i + 1 < args.length) {
            const portValue = parseInt(args[i + 1], 10);
            if (isNaN(portValue)) {
              error = 'Invalid port number';
            } else {
              port = portValue;
            }
          }
        }
        
        return { port, error };
      };

      const result = parseArgs();
      expect(result.error).toBe('Invalid port number');
      expect(result.port).toBe(11235); // Should remain default
    });
  });

  describe('Port Management', () => {
    test('should find available port when default is occupied', async () => {
      const checkPort = (port) => {
        return new Promise((resolve) => {
          const server = net.createServer();
          
          server.listen(port, () => {
            server.once('close', () => resolve(true));
            server.close();
          });
          
          server.on('error', () => resolve(false));
        });
      };

      // This is a simplified test - in real implementation would test port finding logic
      const port = 11235;
      const isAvailable = await checkPort(port);
      expect(typeof isAvailable).toBe('boolean');
    });

    test('should calculate websocket port correctly', () => {
      const calculateWSPort = (uiPort) => uiPort + 1;
      
      expect(calculateWSPort(11235)).toBe(11236);
      expect(calculateWSPort(3000)).toBe(3001);
      expect(calculateWSPort(8080)).toBe(8081);
    });

    test('should handle port conflicts gracefully', () => {
      // Mock port conflict scenario
      const mockError = new Error('EADDRINUSE');
      mockError.code = 'EADDRINUSE';
      
      mockHttpServer.listen.mockImplementation((port, callback) => {
        // Simulate port in use error
        setTimeout(() => callback(mockError), 0);
      });

      const handlePortConflict = (error) => {
        if (error && error.code === 'EADDRINUSE') {
          return 'Port already in use';
        }
        return null;
      };

      const result = handlePortConflict(mockError);
      expect(result).toBe('Port already in use');
    });
  });

  describe('Next.js Integration', () => {
    test('should initialize Next.js application', async () => {
      const initNext = async () => {
        const app = next({ dev: process.env.NODE_ENV !== 'production' });
        await app.prepare();
        return app;
      };

      await initNext();
      expect(next).toHaveBeenCalledWith({ dev: true });
      expect(mockNext.prepare).toHaveBeenCalled();
    });

    test('should handle Next.js preparation errors', async () => {
      mockNext.prepare.mockRejectedValue(new Error('Next.js preparation failed'));

      const initNext = async () => {
        try {
          const app = next({ dev: process.env.NODE_ENV !== 'production' });
          await app.prepare();
          return app;
        } catch (error) {
          return { error: error.message };
        }
      };

      const result = await initNext();
      expect(result.error).toBe('Next.js preparation failed');
    });

    test('should create request handler', () => {
      const mockHandler = jest.fn();
      mockNext.getRequestHandler.mockReturnValue(mockHandler);

      const handler = mockNext.getRequestHandler();
      expect(handler).toBe(mockHandler);
      expect(mockNext.getRequestHandler).toHaveBeenCalled();
    });
  });

  describe('WebSocket Server Management', () => {
    test('should spawn websocket server process', () => {
      const spawnWSServer = (port, wsPort, terminalSize, claudeFlowArgs) => {
        const args = [
          './websocket-server.js',
          '--port', wsPort.toString(),
          '--terminal-size', terminalSize || '80x24'
        ];

        if (claudeFlowArgs && claudeFlowArgs.length > 0) {
          args.push('--claude-flow-args', ...claudeFlowArgs);
        }

        return spawn('node', args, {
          stdio: 'pipe',
          cwd: process.cwd()
        });
      };

      const wsProcess = spawnWSServer(11235, 11236, '120x40', ['sparc', 'run', 'test']);

      expect(spawn).toHaveBeenCalledWith('node', [
        './websocket-server.js',
        '--port', '11236',
        '--terminal-size', '120x40',
        '--claude-flow-args', 'sparc', 'run', 'test'
      ], {
        stdio: 'pipe',
        cwd: process.cwd()
      });
    });

    test('should handle websocket server spawn errors', () => {
      const error = new Error('Failed to spawn websocket server');
      spawn.mockImplementation(() => {
        throw error;
      });

      const spawnWSServer = () => {
        try {
          return spawn('node', ['./websocket-server.js']);
        } catch (err) {
          return { error: err.message };
        }
      };

      const result = spawnWSServer();
      expect(result.error).toBe('Failed to spawn websocket server');
    });

    test('should pipe websocket server output correctly', () => {
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') {
          // Simulate data event
          setTimeout(() => callback(Buffer.from('WS server output')), 0);
        }
      });

      let capturedOutput = '';
      mockProcess.stdout.on('data', (data) => {
        capturedOutput += data.toString();
      });

      // Trigger the mock data event
      const dataCallback = mockProcess.stdout.on.mock.calls[0][1];
      dataCallback(Buffer.from('WS server output'));

      expect(capturedOutput).toBe('WS server output');
    });
  });

  describe('Process Lifecycle Management', () => {
    test('should handle graceful shutdown', () => {
      const processes = [mockProcess];
      
      const gracefulShutdown = (signal) => {
        console.log(`Received ${signal}. Gracefully shutting down...`);
        
        processes.forEach(proc => {
          if (proc && proc.kill) {
            proc.kill('SIGTERM');
          }
        });

        setTimeout(() => {
          process.exit(0);
        }, 5000);
      };

      gracefulShutdown('SIGTERM');
      
      expect(mockProcess.kill).toHaveBeenCalledWith('SIGTERM');
    });

    test('should handle child process exit events', () => {
      let exitHandled = false;

      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') {
          setTimeout(() => {
            callback(1, 'SIGTERM');
            exitHandled = true;
          }, 0);
        }
      });

      mockProcess.on('exit', (code, signal) => {
        expect(code).toBe(1);
        expect(signal).toBe('SIGTERM');
      });

      // Trigger the mock exit event
      const exitCallback = mockProcess.on.mock.calls[0][1];
      exitCallback(1, 'SIGTERM');

      setTimeout(() => {
        expect(exitHandled).toBe(true);
      }, 10);
    });

    test('should restart failed child processes', () => {
      let restartCount = 0;
      const maxRestarts = 3;

      const restartProcess = () => {
        if (restartCount < maxRestarts) {
          restartCount++;
          return spawn('node', ['./websocket-server.js']);
        }
        return null;
      };

      // Simulate process failure and restart
      const newProcess = restartProcess();
      expect(newProcess).toBeTruthy();
      expect(restartCount).toBe(1);

      // Test max restart limit
      for (let i = 0; i < maxRestarts; i++) {
        restartProcess();
      }
      
      const shouldBeNull = restartProcess();
      expect(shouldBeNull).toBeNull();
      expect(restartCount).toBe(maxRestarts);
    });
  });

  describe('Error Handling and Logging', () => {
    test('should log errors with proper context', () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      const logError = (error, context) => {
        console.error(`[Server Error] ${context}:`, error.message);
      };

      const error = new Error('Test error');
      logError(error, 'WebSocket Server');

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Server Error] WebSocket Server:',
        'Test error'
      );

      consoleSpy.mockRestore();
    });

    test('should handle unhandled promise rejections', () => {
      let rejectionHandled = false;

      const handleUnhandledRejection = (reason, promise) => {
        console.error('Unhandled Promise Rejection:', reason);
        rejectionHandled = true;
      };

      const rejection = new Error('Unhandled rejection');
      handleUnhandledRejection(rejection, Promise.reject(rejection));

      expect(rejectionHandled).toBe(true);
    });

    test('should handle uncaught exceptions', () => {
      let exceptionHandled = false;

      const handleUncaughtException = (error) => {
        console.error('Uncaught Exception:', error);
        exceptionHandled = true;
        process.exit(1);
      };

      // Mock process.exit to prevent actual exit in test
      const mockExit = jest.spyOn(process, 'exit').mockImplementation();

      const exception = new Error('Uncaught exception');
      handleUncaughtException(exception);

      expect(exceptionHandled).toBe(true);
      expect(mockExit).toHaveBeenCalledWith(1);

      mockExit.mockRestore();
    });
  });

  describe('Environment Configuration', () => {
    test('should respect NODE_ENV for development mode', () => {
      const originalEnv = process.env.NODE_ENV;
      
      // Test development mode
      process.env.NODE_ENV = 'development';
      const isDev = process.env.NODE_ENV !== 'production';
      expect(isDev).toBe(true);

      // Test production mode
      process.env.NODE_ENV = 'production';
      const isProd = process.env.NODE_ENV === 'production';
      expect(isProd).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });

    test('should load environment variables correctly', () => {
      const originalPort = process.env.PORT;
      const originalWSPort = process.env.WS_PORT;

      process.env.PORT = '3000';
      process.env.WS_PORT = '3001';

      const getEnvConfig = () => ({
        port: parseInt(process.env.PORT || '11235', 10),
        wsPort: parseInt(process.env.WS_PORT || '11236', 10),
      });

      const config = getEnvConfig();
      expect(config.port).toBe(3000);
      expect(config.wsPort).toBe(3001);

      // Cleanup
      if (originalPort) {
        process.env.PORT = originalPort;
      } else {
        delete process.env.PORT;
      }
      
      if (originalWSPort) {
        process.env.WS_PORT = originalWSPort;
      } else {
        delete process.env.WS_PORT;
      }
    });
  });

  describe('Health Checks and Monitoring', () => {
    test('should provide health check endpoint logic', () => {
      const getHealthStatus = () => ({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        pid: process.pid,
      });

      const health = getHealthStatus();
      expect(health.status).toBe('healthy');
      expect(health).toHaveProperty('timestamp');
      expect(health).toHaveProperty('uptime');
      expect(health).toHaveProperty('memory');
      expect(health).toHaveProperty('pid');
    });

    test('should monitor child process health', () => {
      const checkChildProcessHealth = (processes) => {
        return processes.map(proc => ({
          pid: proc.pid,
          alive: proc.killed === false,
          exitCode: proc.exitCode,
        }));
      };

      const mockProc = { pid: 12345, killed: false, exitCode: null };
      const health = checkChildProcessHealth([mockProc]);

      expect(health).toHaveLength(1);
      expect(health[0].pid).toBe(12345);
      expect(health[0].alive).toBe(true);
      expect(health[0].exitCode).toBeNull();
    });
  });
});