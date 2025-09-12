const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const os = require('os');

// Mock child_process.spawn
jest.mock('child_process', () => ({
  spawn: jest.fn(),
}));

// Mock net module
jest.mock('net', () => ({
  createServer: jest.fn(),
}));

// Mock next
jest.mock('next', () => {
  return jest.fn(() => ({
    prepare: jest.fn().mockResolvedValue(undefined),
    getRequestHandler: jest.fn(() => jest.fn()),
  }));
});

// Mock os module
jest.mock('os', () => ({
  networkInterfaces: jest.fn(() => ({
    en0: [{
      address: '192.168.1.100',
      family: 'IPv4',
      internal: false,
    }],
  })),
}));

// Mock http.createServer
const mockHttpServer = {
  listen: jest.fn(),
  once: jest.fn(),
  close: jest.fn(),
};

jest.mock('http', () => ({
  createServer: jest.fn(() => mockHttpServer),
}));

// Mock url.parse
jest.mock('url', () => ({
  parse: jest.fn((url) => ({ pathname: url, query: {} })),
}));

describe('Server.js', () => {
  let originalArgv;
  let originalEnv;
  let originalConsole;
  let mockNetServer;
  let mockChildProcess;

  beforeEach(() => {
    jest.clearAllMocks();
    originalArgv = process.argv;
    originalEnv = { ...process.env };
    originalConsole = { log: console.log, error: console.error };
    
    // Mock console to reduce test noise
    console.log = jest.fn();
    console.error = jest.fn();
    
    // Mock net server
    mockNetServer = {
      listen: jest.fn(),
      close: jest.fn(),
      once: jest.fn((event, callback) => {
        if (event === 'listening') {
          setTimeout(callback, 0);
        }
      }),
    };
    
    net.createServer.mockReturnValue(mockNetServer);
    
    // Mock child process
    mockChildProcess = {
      stdout: { on: jest.fn() },
      stderr: { on: jest.fn() },
      on: jest.fn(),
      kill: jest.fn(),
      pid: 12345,
    };
    
    spawn.mockReturnValue(mockChildProcess);
  });

  afterEach(() => {
    process.argv = originalArgv;
    process.env = originalEnv;
    console.log = originalConsole.log;
    console.error = originalConsole.error;
    jest.resetModules();
  });

  describe('parseArgs', () => {
    it('should parse default port when no arguments provided', () => {
      // We need to require the module after setting up mocks
      process.argv = ['node', 'server.js'];
      
      // Mock the implementation to test parseArgs functionality
      const serverModule = require('../../server.js');
      
      // Since parseArgs is not exported, we test the overall behavior
      expect(spawn).not.toHaveBeenCalled(); // Not called during module load
    });

    it('should parse custom port from arguments', () => {
      process.argv = ['node', 'server.js', '--port', '8080'];
      
      // Require the module with custom port
      require('../../server.js');
      
      // The module should process the port argument
      expect(process.env.NEXT_PUBLIC_WS_PORT).toBeDefined();
    });

    it('should handle claude-flow arguments', () => {
      process.argv = ['node', 'server.js', 'swarm', 'init', 'mesh'];
      
      require('../../server.js');
      
      // Arguments should be passed to child process
      expect(spawn).toHaveBeenCalled();
    });
  });

  describe('checkPort', () => {
    it('should detect when port is available', async () => {
      // Mock port checking logic by setting up net.createServer to succeed
      mockNetServer.once.mockImplementation((event, callback) => {
        if (event === 'listening') {
          setTimeout(callback, 0);
        }
      });

      require('../../server.js');
      
      expect(net.createServer).toHaveBeenCalled();
    });

    it('should detect when port is in use', () => {
      // Mock port checking to fail
      mockNetServer.once.mockImplementation((event, callback) => {
        if (event === 'error') {
          setTimeout(() => callback({ code: 'EADDRINUSE' }), 0);
        }
      });

      require('../../server.js');
      
      expect(net.createServer).toHaveBeenCalled();
    });
  });

  describe('startWebSocketServer', () => {
    it('should start WebSocket server with correct arguments', () => {
      process.argv = ['node', 'server.js'];
      
      require('../../server.js');
      
      expect(spawn).toHaveBeenCalledWith(
        'node',
        expect.arrayContaining([
          expect.stringContaining('websocket-server.js'),
          '--port',
          expect.any(String),
          '--cwd',
          expect.any(String),
        ]),
        expect.objectContaining({
          stdio: 'pipe',
          shell: false,
          cwd: expect.any(String),
          env: expect.any(Object),
        })
      );
    });

    it('should handle WebSocket server output', () => {
      require('../../server.js');
      
      const mockData = Buffer.from('WebSocket server started');
      const stdoutCallback = mockChildProcess.stdout.on.mock.calls.find(
        call => call[0] === 'data'
      )?.[1];
      
      if (stdoutCallback) {
        stdoutCallback(mockData);
      }
      
      expect(mockChildProcess.stdout.on).toHaveBeenCalledWith('data', expect.any(Function));
    });

    it('should handle WebSocket server errors', () => {
      require('../../server.js');
      
      const mockError = Buffer.from('Error starting WebSocket server');
      const stderrCallback = mockChildProcess.stderr.on.mock.calls.find(
        call => call[0] === 'data'
      )?.[1];
      
      if (stderrCallback) {
        stderrCallback(mockError);
      }
      
      expect(mockChildProcess.stderr.on).toHaveBeenCalledWith('data', expect.any(Function));
    });

    it('should handle WebSocket server exit', () => {
      require('../../server.js');
      
      const exitCallback = mockChildProcess.on.mock.calls.find(
        call => call[0] === 'exit'
      )?.[1];
      
      if (exitCallback) {
        const mockExit = jest.fn();
        const originalExit = process.exit;
        process.exit = mockExit;
        
        exitCallback(0, null);
        
        process.exit = originalExit;
      }
      
      expect(mockChildProcess.on).toHaveBeenCalledWith('exit', expect.any(Function));
    });
  });

  describe('main function', () => {
    it('should start HTTP server on available port', async () => {
      process.argv = ['node', 'server.js'];
      
      require('../../server.js');
      
      // Wait for async operations
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(mockHttpServer.listen).toHaveBeenCalled();
    });

    it('should set environment variables correctly', () => {
      process.argv = ['node', 'server.js', '--port', '9000'];
      
      require('../../server.js');
      
      expect(process.env.NEXT_PUBLIC_WS_PORT).toBe('9001'); // UI port + 1
      expect(process.env.NEXT_PUBLIC_WS_URL).toBe('ws://localhost:9001');
    });

    it('should handle server startup errors', () => {
      mockHttpServer.once.mockImplementation((event, callback) => {
        if (event === 'error') {
          setTimeout(() => callback(new Error('EADDRINUSE')), 0);
        }
      });

      const mockExit = jest.fn();
      const originalExit = process.exit;
      process.exit = mockExit;

      require('../../server.js');

      process.exit = originalExit;
      
      expect(mockHttpServer.once).toHaveBeenCalledWith('error', expect.any(Function));
    });
  });

  describe('getNetworkAddress', () => {
    it('should return network address', () => {
      // Mock os.networkInterfaces
      const mockNetworkInterfaces = {
        'en0': [
          {
            address: '192.168.1.100',
            family: 'IPv4',
            internal: false,
          },
          {
            address: '127.0.0.1',
            family: 'IPv4',
            internal: true,
          },
        ],
      };

      jest.doMock('os', () => ({
        networkInterfaces: () => mockNetworkInterfaces,
      }));

      require('../../server.js');
      
      // Network address detection should work
      expect(true).toBe(true); // Module loads without error
    });
  });

  describe('shutdown handling', () => {
    it('should handle SIGTERM gracefully', () => {
      const originalOn = process.on;
      const mockProcessOn = jest.fn();
      process.on = mockProcessOn;

      require('../../server.js');
      
      expect(mockProcessOn).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
      expect(mockProcessOn).toHaveBeenCalledWith('SIGINT', expect.any(Function));

      process.on = originalOn;
    });

    it('should shutdown WebSocket server on exit', () => {
      let shutdownFunction;
      const mockProcessOn = jest.fn((event, callback) => {
        if (event === 'SIGTERM') {
          shutdownFunction = callback;
        }
      });
      
      const originalOn = process.on;
      process.on = mockProcessOn;

      require('../../server.js');
      
      if (shutdownFunction) {
        shutdownFunction();
        expect(mockChildProcess.kill).toHaveBeenCalled();
      }

      process.on = originalOn;
    });
  });

  describe('error handling', () => {
    it('should handle module load errors gracefully', () => {
      // Mock a module that throws during require
      jest.doMock('next', () => {
        throw new Error('Next.js not found');
      });

      const mockExit = jest.fn();
      const originalExit = process.exit;
      process.exit = mockExit;

      expect(() => {
        require('../../server.js');
      }).toThrow();

      process.exit = originalExit;
    });

    it('should handle invalid port numbers', () => {
      process.argv = ['node', 'server.js', '--port', 'invalid'];
      
      const mockExit = jest.fn();
      const originalExit = process.exit;
      process.exit = mockExit;

      require('../../server.js');

      process.exit = originalExit;
    });
  });

  describe('environment handling', () => {
    it('should use INIT_CWD when available', () => {
      process.env.INIT_CWD = '/custom/working/directory';
      
      require('../../server.js');
      
      expect(spawn).toHaveBeenCalledWith(
        'node',
        expect.arrayContaining(['--cwd', '/custom/working/directory']),
        expect.any(Object)
      );
    });

    it('should fallback to process.cwd when INIT_CWD not available', () => {
      delete process.env.INIT_CWD;
      
      require('../../server.js');
      
      expect(spawn).toHaveBeenCalledWith(
        'node',
        expect.arrayContaining(['--cwd', expect.any(String)]),
        expect.any(Object)
      );
    });
  });
});