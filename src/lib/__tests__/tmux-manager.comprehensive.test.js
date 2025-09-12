/**
 * @jest-environment node
 */

const TmuxManager = require('../tmux-manager');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

// Mock child_process
jest.mock('child_process', () => ({
  spawn: jest.fn()
}));

// Mock fs
jest.mock('fs', () => ({
  existsSync: jest.fn(),
  mkdirSync: jest.fn(),
  unlinkSync: jest.fn(),
  readdirSync: jest.fn()
}));

// Mock path
jest.mock('path', () => ({
  join: jest.fn((...args) => args.join('/')),
}));

// Mock crypto for consistent tests
jest.mock('crypto', () => ({
  randomBytes: jest.fn().mockReturnValue(Buffer.from('abcd', 'hex'))
}));

// Mock console methods
global.console = {
  ...console,
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn()
};

describe('TmuxManager Comprehensive Tests', () => {
  let tmuxManager;
  let mockProcess;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create a new TmuxManager instance
    tmuxManager = new TmuxManager('/test/workingdir');
    
    // Create a mock process that extends EventEmitter
    mockProcess = new EventEmitter();
    mockProcess.stdout = new EventEmitter();
    mockProcess.stderr = new EventEmitter();
    mockProcess.stdin = { end: jest.fn() };
    
    // Mock spawn to return our mock process
    spawn.mockReturnValue(mockProcess);
    
    // Mock fs.existsSync to return false initially
    fs.existsSync.mockReturnValue(false);
    
    // Mock Date.now for consistent timestamps
    jest.spyOn(Date, 'now').mockReturnValue(1234567890123);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Constructor', () => {
    test('should initialize with default working directory', () => {
      const manager = new TmuxManager();
      expect(manager.workingDir).toBe(process.cwd());
    });

    test('should initialize with custom working directory', () => {
      const manager = new TmuxManager('/custom/dir');
      expect(manager.workingDir).toBe('/custom/dir');
    });

    test('should set up socket directory', () => {
      expect(tmuxManager.socketDir).toBe('/tmp/.claude-flow-sockets');
      expect(tmuxManager.sessionPrefix).toBe('cf');
    });

    test('should create socket directory if it does not exist', () => {
      fs.existsSync.mockReturnValue(false);
      new TmuxManager();
      
      expect(fs.mkdirSync).toHaveBeenCalledWith('/tmp/.claude-flow-sockets', { recursive: true });
    });

    test('should not create socket directory if it exists', () => {
      fs.existsSync.mockReturnValue(true);
      new TmuxManager();
      
      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });
  });

  describe('isTmuxAvailable', () => {
    test('should return true when tmux is available', async () => {
      const promise = tmuxManager.isTmuxAvailable();
      
      // Simulate successful tmux version check
      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      const result = await promise;
      expect(result).toBe(true);
      expect(spawn).toHaveBeenCalledWith('tmux', ['-V'], { stdio: 'pipe' });
    });

    test('should return false when tmux is not available', async () => {
      const promise = tmuxManager.isTmuxAvailable();
      
      // Simulate tmux not found
      process.nextTick(() => {
        mockProcess.emit('exit', 1);
      });

      const result = await promise;
      expect(result).toBe(false);
    });

    test('should return false when tmux command errors', async () => {
      const promise = tmuxManager.isTmuxAvailable();
      
      // Simulate spawn error
      process.nextTick(() => {
        mockProcess.emit('error', new Error('Command not found'));
      });

      const result = await promise;
      expect(result).toBe(false);
    });
  });

  describe('generateSessionName', () => {
    test('should generate session name with correct format', () => {
      const sessionName = tmuxManager.generateSessionName();
      expect(sessionName).toBe('cf-1234567890123-abcd');
    });

    test('should generate unique session names', () => {
      // Mock different timestamps and random values
      Date.now.mockReturnValueOnce(1111).mockReturnValueOnce(2222);
      
      const crypto = require('crypto');
      crypto.randomBytes.mockReturnValueOnce(Buffer.from('1111', 'hex'))
                         .mockReturnValueOnce(Buffer.from('2222', 'hex'));

      const name1 = tmuxManager.generateSessionName();
      const name2 = tmuxManager.generateSessionName();

      expect(name1).not.toBe(name2);
      expect(name1).toBe('cf-1111-1111');
      expect(name2).toBe('cf-2222-2222');
    });
  });

  describe('getSocketPath', () => {
    test('should return correct socket path', () => {
      const socketPath = tmuxManager.getSocketPath('test-session');
      expect(socketPath).toBe('/tmp/.claude-flow-sockets/test-session.sock');
    });
  });

  describe('createSession', () => {
    test('should create session successfully with default parameters', async () => {
      const promise = tmuxManager.createSession();

      // Simulate successful session creation
      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      const sessionInfo = await promise;

      expect(sessionInfo.name).toBe('cf-1234567890123-abcd');
      expect(sessionInfo.socketPath).toBe('/tmp/.claude-flow-sockets/cf-1234567890123-abcd.sock');
      expect(sessionInfo.workingDir).toBe('/test/workingdir');
      expect(sessionInfo.command).toBe(null);
      expect(sessionInfo.args).toEqual([]);
    });

    test('should create session with custom name', async () => {
      const promise = tmuxManager.createSession('custom-session');

      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      const sessionInfo = await promise;
      expect(sessionInfo.name).toBe('custom-session');
    });

    test('should create session with command and args', async () => {
      const promise = tmuxManager.createSession('test-session', 'npm', ['start'], 120, 30);

      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      const sessionInfo = await promise;

      expect(sessionInfo.command).toBe('npm');
      expect(sessionInfo.args).toEqual(['start']);
      
      // Verify spawn was called with correct arguments
      const spawnArgs = spawn.mock.calls[0][1];
      expect(spawnArgs).toContain('-x');
      expect(spawnArgs).toContain('120');
      expect(spawnArgs).toContain('-y');
      expect(spawnArgs).toContain('30');
    });

    test('should handle session creation failure', async () => {
      const promise = tmuxManager.createSession();

      process.nextTick(() => {
        mockProcess.stderr.emit('data', 'Error creating session');
        mockProcess.emit('exit', 1);
      });

      await expect(promise).rejects.toThrow('Tmux session creation failed: Error creating session');
    });

    test('should handle spawn error', async () => {
      const promise = tmuxManager.createSession();

      process.nextTick(() => {
        mockProcess.emit('error', new Error('Spawn failed'));
      });

      await expect(promise).rejects.toThrow('Spawn failed');
    });

    test('should set environment variables correctly', async () => {
      const promise = tmuxManager.createSession('test', null, [], 100, 25);

      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      await promise;

      const spawnOptions = spawn.mock.calls[0][2];
      expect(spawnOptions.env.TERM).toBe('xterm-256color');
      expect(spawnOptions.env.COLORTERM).toBe('truecolor');
      expect(spawnOptions.env.COLUMNS).toBe('100');
      expect(spawnOptions.env.LINES).toBe('25');
    });
  });

  describe('sessionExists', () => {
    test('should return true when session exists', async () => {
      const promise = tmuxManager.sessionExists('test-session', '/test/socket');

      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      const result = await promise;
      expect(result).toBe(true);
      expect(spawn).toHaveBeenCalledWith('tmux', [
        '-S', '/test/socket',
        'has-session',
        '-t', 'test-session'
      ], { stdio: 'pipe' });
    });

    test('should return false when session does not exist', async () => {
      const promise = tmuxManager.sessionExists('test-session', '/test/socket');

      process.nextTick(() => {
        mockProcess.emit('exit', 1);
      });

      const result = await promise;
      expect(result).toBe(false);
    });

    test('should return false on error', async () => {
      const promise = tmuxManager.sessionExists('test-session', '/test/socket');

      process.nextTick(() => {
        mockProcess.emit('error', new Error('Test error'));
      });

      const result = await promise;
      expect(result).toBe(false);
    });
  });

  describe('connectToSession', () => {
    beforeEach(() => {
      // Add a session to activeSessions
      tmuxManager.activeSessions.set('test-session', {
        name: 'test-session',
        socketPath: '/test/socket',
        created: Date.now(),
        workingDir: '/test/workingdir',
        command: null,
        args: []
      });
    });

    test('should throw error if session not found', async () => {
      await expect(tmuxManager.connectToSession('nonexistent')).rejects.toThrow('Session nonexistent not found');
    });

    test('should throw error if session no longer exists', async () => {
      // Mock sessionExists to return false
      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(false);

      await expect(tmuxManager.connectToSession('test-session')).rejects.toThrow('Session test-session no longer exists');
      expect(tmuxManager.activeSessions.has('test-session')).toBe(false);
    });

    test('should return PTY interface for valid session', async () => {
      // Mock sessionExists to return true
      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(true);
      jest.spyOn(tmuxManager, 'capturePane').mockResolvedValue('initial output');
      jest.spyOn(tmuxManager, 'captureFullScreen').mockResolvedValue('full screen');

      const ptyInterface = await tmuxManager.connectToSession('test-session');

      expect(ptyInterface).toHaveProperty('sessionName', 'test-session');
      expect(ptyInterface).toHaveProperty('socketPath', '/test/socket');
      expect(ptyInterface).toHaveProperty('write');
      expect(ptyInterface).toHaveProperty('onData');
      expect(ptyInterface).toHaveProperty('onExit');
      expect(ptyInterface).toHaveProperty('resize');
      expect(ptyInterface).toHaveProperty('cleanup');
    });
  });

  describe('capturePane', () => {
    test('should capture pane content successfully', async () => {
      const promise = tmuxManager.capturePane('test-session', '/test/socket');

      process.nextTick(() => {
        mockProcess.stdout.emit('data', 'test output');
        mockProcess.emit('exit', 0);
      });

      const output = await promise;
      expect(output).toBe('test output');
    });

    test('should handle capture failure', async () => {
      const promise = tmuxManager.capturePane('test-session', '/test/socket');

      process.nextTick(() => {
        mockProcess.emit('exit', 1);
      });

      await expect(promise).rejects.toThrow('Failed to capture pane');
    });
  });

  describe('captureFullScreen', () => {
    test('should capture full screen with correct line count', async () => {
      const promise = tmuxManager.captureFullScreen('test-session', '/test/socket', 3);

      process.nextTick(() => {
        mockProcess.stdout.emit('data', 'line1\nline2\n');
        mockProcess.emit('exit', 0);
      });

      const output = await promise;
      expect(output.split('\n')).toHaveLength(3); // Should pad to 3 lines
    });

    test('should trim excess lines', async () => {
      const promise = tmuxManager.captureFullScreen('test-session', '/test/socket', 2);

      process.nextTick(() => {
        mockProcess.stdout.emit('data', 'line1\nline2\nline3\nline4\n');
        mockProcess.emit('exit', 0);
      });

      const output = await promise;
      const lines = output.split('\n');
      expect(lines).toHaveLength(2);
      expect(lines[0]).toBe('line3');
      expect(lines[1]).toBe('line4');
    });
  });

  describe('sendKeysToSession', () => {
    test('should send keys to session', () => {
      tmuxManager.sendKeysToSession('test-session', '/test/socket', 'test input');

      expect(spawn).toHaveBeenCalledWith('tmux', [
        '-S', '/test/socket',
        'send-keys',
        '-t', 'test-session',
        '-l',
        'test input'
      ], { stdio: 'ignore' });
    });
  });

  describe('killSession', () => {
    beforeEach(() => {
      tmuxManager.activeSessions.set('test-session', {
        name: 'test-session',
        socketPath: '/test/socket',
        created: Date.now()
      });
      
      jest.spyOn(tmuxManager, 'cleanupSocket').mockImplementation();
    });

    test('should kill session successfully', async () => {
      const promise = tmuxManager.killSession('test-session');

      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      await promise;

      expect(spawn).toHaveBeenCalledWith('tmux', [
        '-S', '/test/socket',
        'kill-session',
        '-t', 'test-session'
      ], { stdio: 'pipe' });

      expect(tmuxManager.activeSessions.has('test-session')).toBe(false);
      expect(tmuxManager.cleanupSocket).toHaveBeenCalledWith('/test/socket');
    });

    test('should handle session not found', async () => {
      await tmuxManager.killSession('nonexistent');
      expect(console.warn).toHaveBeenCalledWith('Session nonexistent not found in active sessions');
    });

    test('should handle kill error gracefully', async () => {
      const promise = tmuxManager.killSession('test-session');

      process.nextTick(() => {
        mockProcess.emit('error', new Error('Kill failed'));
      });

      await promise; // Should not throw
      expect(console.error).toHaveBeenCalledWith('❌ Error killing tmux session: Kill failed');
    });
  });

  describe('cleanupSocket', () => {
    test('should remove existing socket file', () => {
      fs.existsSync.mockReturnValue(true);
      
      tmuxManager.cleanupSocket('/test/socket');

      expect(fs.unlinkSync).toHaveBeenCalledWith('/test/socket');
    });

    test('should handle non-existent socket file', () => {
      fs.existsSync.mockReturnValue(false);
      
      tmuxManager.cleanupSocket('/test/socket');

      expect(fs.unlinkSync).not.toHaveBeenCalled();
    });

    test('should handle cleanup error', () => {
      fs.existsSync.mockReturnValue(true);
      fs.unlinkSync.mockImplementation(() => {
        throw new Error('Permission denied');
      });

      tmuxManager.cleanupSocket('/test/socket');

      expect(console.warn).toHaveBeenCalledWith('⚠️  Failed to clean up socket /test/socket: Permission denied');
    });
  });

  describe('getActiveSessions', () => {
    test('should return empty array initially', () => {
      const sessions = tmuxManager.getActiveSessions();
      expect(sessions).toEqual([]);
    });

    test('should return active sessions', () => {
      const sessionInfo = { name: 'test', socketPath: '/test' };
      tmuxManager.activeSessions.set('test', sessionInfo);

      const sessions = tmuxManager.getActiveSessions();
      expect(sessions).toEqual([sessionInfo]);
    });
  });

  describe('cleanup', () => {
    beforeEach(() => {
      jest.spyOn(tmuxManager, 'killSession').mockResolvedValue();
      fs.readdirSync.mockReturnValue(['session1.sock', 'session2.sock', 'other.file']);
      jest.spyOn(tmuxManager, 'cleanupSocket').mockImplementation();
    });

    test('should clean up all sessions and sockets', async () => {
      tmuxManager.activeSessions.set('session1', { name: 'session1' });
      tmuxManager.activeSessions.set('session2', { name: 'session2' });

      fs.existsSync.mockReturnValue(true);

      await tmuxManager.cleanup();

      expect(tmuxManager.killSession).toHaveBeenCalledWith('session1');
      expect(tmuxManager.killSession).toHaveBeenCalledWith('session2');
      expect(tmuxManager.cleanupSocket).toHaveBeenCalledWith('/tmp/.claude-flow-sockets/session1.sock');
      expect(tmuxManager.cleanupSocket).toHaveBeenCalledWith('/tmp/.claude-flow-sockets/session2.sock');
    });

    test('should handle cleanup errors', async () => {
      fs.existsSync.mockReturnValue(true);
      fs.readdirSync.mockImplementation(() => {
        throw new Error('Read error');
      });

      await tmuxManager.cleanup(); // Should not throw

      expect(console.warn).toHaveBeenCalledWith('⚠️  Error during socket cleanup: Read error');
    });
  });

  describe('sendCommand', () => {
    beforeEach(() => {
      tmuxManager.activeSessions.set('test-session', {
        name: 'test-session',
        socketPath: '/test/socket'
      });
    });

    test('should send command successfully', async () => {
      const promise = tmuxManager.sendCommand('test-session', 'ls -la');

      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      await promise;

      expect(spawn).toHaveBeenCalledWith('tmux', [
        '-S', '/test/socket',
        'send-keys',
        '-t', 'test-session',
        'ls -la',
        'Enter'
      ], { stdio: 'pipe' });
    });

    test('should handle command send failure', async () => {
      const promise = tmuxManager.sendCommand('test-session', 'ls');

      process.nextTick(() => {
        mockProcess.emit('exit', 1);
      });

      await expect(promise).rejects.toThrow('Failed to send command to session test-session');
    });

    test('should throw error for non-existent session', async () => {
      await expect(tmuxManager.sendCommand('nonexistent', 'ls')).rejects.toThrow('Session nonexistent not found');
    });
  });

  describe('Edge cases and error handling', () => {
    test('should handle very long session names', () => {
      const longName = 'a'.repeat(200);
      const socketPath = tmuxManager.getSocketPath(longName);
      expect(socketPath).toBe(`/tmp/.claude-flow-sockets/${longName}.sock`);
    });

    test('should handle special characters in commands', async () => {
      tmuxManager.activeSessions.set('test', { socketPath: '/test' });
      
      const promise = tmuxManager.sendCommand('test', 'echo "hello & world"');
      
      process.nextTick(() => {
        mockProcess.emit('exit', 0);
      });

      await promise;

      expect(spawn).toHaveBeenCalledWith('tmux', expect.arrayContaining(['echo "hello & world"']), expect.any(Object));
    });

    test('should handle concurrent operations', async () => {
      const promises = [];
      
      for (let i = 0; i < 5; i++) {
        promises.push(tmuxManager.createSession(`session-${i}`));
      }

      // Complete all sessions
      process.nextTick(() => {
        for (let i = 0; i < 5; i++) {
          mockProcess.emit('exit', 0);
        }
      });

      const results = await Promise.all(promises);
      expect(results).toHaveLength(5);
      expect(tmuxManager.activeSessions.size).toBe(5);
    });
  });

  describe('Performance tests', () => {
    test('should handle many sessions efficiently', async () => {
      const startTime = Date.now();
      const promises = [];

      // Create 10 sessions concurrently
      for (let i = 0; i < 10; i++) {
        promises.push(tmuxManager.createSession(`perf-test-${i}`));
      }

      // Complete all operations quickly
      process.nextTick(() => {
        for (let i = 0; i < 10; i++) {
          mockProcess.emit('exit', 0);
        }
      });

      await Promise.all(promises);
      
      const endTime = Date.now();
      expect(endTime - startTime).toBeLessThan(100); // Should complete quickly
      expect(tmuxManager.activeSessions.size).toBe(10);
    });
  });
});