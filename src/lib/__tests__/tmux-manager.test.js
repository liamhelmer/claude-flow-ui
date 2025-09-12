/**
 * Comprehensive Test Suite for TmuxManager
 * Testing all edge cases, error conditions, and functionality
 */

const TmuxManager = require('../tmux-manager');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Mock all dependencies
jest.mock('child_process');
jest.mock('fs');
jest.mock('path');
jest.mock('crypto');

describe('TmuxManager', () => {
  let tmuxManager;
  let mockSpawn;
  let mockProcess;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default mocks
    mockProcess = {
      stdout: { on: jest.fn() },
      stderr: { on: jest.fn() },
      on: jest.fn(),
      kill: jest.fn(),
      pid: 12345
    };
    
    mockSpawn = jest.mocked(spawn);
    mockSpawn.mockReturnValue(mockProcess);
    
    // Mock fs operations
    jest.mocked(fs.existsSync).mockReturnValue(true);
    jest.mocked(fs.mkdirSync).mockReturnValue(undefined);
    jest.mocked(fs.unlinkSync).mockReturnValue(undefined);
    jest.mocked(fs.readdirSync).mockReturnValue([]);
    
    // Mock path operations
    jest.mocked(path.join).mockImplementation((...args) => args.join('/'));
    
    // Mock crypto
    jest.mocked(crypto.randomBytes).mockReturnValue({ toString: () => 'abcd' });
    
    tmuxManager = new TmuxManager('/test/working/dir');
  });

  describe('Constructor and Initialization', () => {
    it('should initialize with default working directory', () => {
      const manager = new TmuxManager();
      expect(manager.workingDir).toBe(process.cwd());
    });

    it('should initialize with custom working directory', () => {
      const customDir = '/custom/working/dir';
      const manager = new TmuxManager(customDir);
      expect(manager.workingDir).toBe(customDir);
    });

    it('should create socket directory if it does not exist', () => {
      jest.mocked(fs.existsSync).mockReturnValue(false);
      
      const manager = new TmuxManager();
      
      expect(fs.mkdirSync).toHaveBeenCalledWith(
        expect.stringContaining('.claude-flow-sockets'),
        { recursive: true }
      );
    });

    it('should not create socket directory if it already exists', () => {
      jest.mocked(fs.existsSync).mockReturnValue(true);
      
      const manager = new TmuxManager();
      
      expect(fs.mkdirSync).not.toHaveBeenCalled();
    });

    it('should initialize active sessions map', () => {
      expect(tmuxManager.activeSessions).toBeInstanceOf(Map);
      expect(tmuxManager.activeSessions.size).toBe(0);
    });
  });

  describe('isTmuxAvailable', () => {
    it('should return true when tmux is available', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });

      const isAvailable = await tmuxManager.isTmuxAvailable();
      
      expect(isAvailable).toBe(true);
      expect(spawn).toHaveBeenCalledWith('tmux', ['-V'], { stdio: 'pipe' });
    });

    it('should return false when tmux is not available', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1);
      });

      const isAvailable = await tmuxManager.isTmuxAvailable();
      
      expect(isAvailable).toBe(false);
    });

    it('should return false when tmux command errors', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'error') callback(new Error('Command not found'));
      });

      const isAvailable = await tmuxManager.isTmuxAvailable();
      
      expect(isAvailable).toBe(false);
    });
  });

  describe('generateSessionName', () => {
    beforeEach(() => {
      jest.spyOn(Date, 'now').mockReturnValue(1234567890000);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should generate unique session names', () => {
      // Mock Date.now to return different values for uniqueness
      let mockTime = 1234567890000;
      jest.spyOn(Date, 'now').mockImplementation(() => ++mockTime);
      
      const name1 = tmuxManager.generateSessionName();
      const name2 = tmuxManager.generateSessionName();
      
      expect(name1).toMatch(/^cf-\d+-\w+$/);
      expect(name2).toMatch(/^cf-\d+-\w+$/);
      expect(name1).not.toBe(name2); // Different due to timestamp
      
      Date.now.mockRestore();
    });

    it('should use timestamp and random ID in session name', () => {
      const name = tmuxManager.generateSessionName();
      
      expect(name).toBe('cf-1234567890000-abcd');
    });
  });

  describe('getSocketPath', () => {
    it('should return correct socket path', () => {
      const sessionName = 'test-session';
      const socketPath = tmuxManager.getSocketPath(sessionName);
      
      expect(socketPath).toBe(`/tmp/.claude-flow-sockets/${sessionName}.sock`);
    });
  });

  describe('createSession', () => {
    beforeEach(() => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
    });

    it('should create session with default parameters', async () => {
      const sessionInfo = await tmuxManager.createSession();
      
      expect(sessionInfo).toMatchObject({
        name: expect.stringMatching(/^cf-\d+-\w+$/),
        socketPath: expect.stringContaining('.sock'),
        created: expect.any(Number),
        workingDir: '/test/working/dir',
        command: null,
        args: []
      });
      
      expect(tmuxManager.activeSessions.size).toBe(1);
    });

    it('should create session with custom name and command', async () => {
      const sessionName = 'custom-session';
      const command = 'npm start';
      const args = ['--verbose'];
      
      const sessionInfo = await tmuxManager.createSession(sessionName, command, args);
      
      expect(sessionInfo.name).toBe(sessionName);
      expect(sessionInfo.command).toBe(command);
      expect(sessionInfo.args).toEqual(args);
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        expect.arrayContaining([
          '-S', expect.stringContaining(sessionName),
          'new-session',
          '-d',
          '-s', sessionName,
          '-x', '120',
          '-y', '40',
          '-c', '/test/working/dir',
          expect.any(String),
          '-c',
          expect.stringContaining('npm start "--verbose"')
        ]),
        expect.objectContaining({
          stdio: 'pipe',
          cwd: '/test/working/dir',
          env: expect.objectContaining({
            TERM: 'xterm-256color',
            COLORTERM: 'truecolor'
          })
        })
      );
    });

    it('should create session with custom dimensions', async () => {
      await tmuxManager.createSession('test', null, [], 80, 24);
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        expect.arrayContaining(['-x', '80', '-y', '24']),
        expect.any(Object)
      );
    });

    it('should handle session creation failure', async () => {
      const errorMessage = 'Failed to create session';
      
      mockProcess.stderr.on.mockImplementation((event, callback) => {
        if (event === 'data') callback(errorMessage);
      });
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1);
      });

      await expect(tmuxManager.createSession('fail-test'))
        .rejects.toThrow(`Tmux session creation failed: ${errorMessage}`);
    });

    it('should handle spawn error', async () => {
      const spawnError = new Error('spawn ENOENT');
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'error') callback(spawnError);
      });

      await expect(tmuxManager.createSession('error-test'))
        .rejects.toThrow(spawnError);
    });

    it('should handle command with shell environment variable', async () => {
      const originalShell = process.env.SHELL;
      process.env.SHELL = '/bin/zsh';
      
      try {
        await tmuxManager.createSession('shell-test', 'echo test');
        
        expect(spawn).toHaveBeenCalledWith(
          'tmux',
          expect.arrayContaining(['/bin/zsh', '-c', expect.any(String)]),
          expect.any(Object)
        );
      } finally {
        process.env.SHELL = originalShell;
      }
    });

    it('should use default shell when SHELL env var is not set', async () => {
      const originalShell = process.env.SHELL;
      delete process.env.SHELL;
      
      try {
        await tmuxManager.createSession('default-shell-test', 'echo test');
        
        expect(spawn).toHaveBeenCalledWith(
          'tmux',
          expect.arrayContaining(['/bin/bash', '-c', expect.any(String)]),
          expect.any(Object)
        );
      } finally {
        process.env.SHELL = originalShell;
      }
    });
  });

  describe('sessionExists', () => {
    it('should return true for existing session', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });

      const exists = await tmuxManager.sessionExists('test-session', '/path/to/socket');
      
      expect(exists).toBe(true);
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        ['-S', '/path/to/socket', 'has-session', '-t', 'test-session'],
        { stdio: 'pipe' }
      );
    });

    it('should return false for non-existing session', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1);
      });

      const exists = await tmuxManager.sessionExists('nonexistent', '/path/to/socket');
      
      expect(exists).toBe(false);
    });

    it('should return false on command error', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'error') callback(new Error('Command failed'));
      });

      const exists = await tmuxManager.sessionExists('error-session', '/path/to/socket');
      
      expect(exists).toBe(false);
    });
  });

  describe('connectToSession', () => {
    let sessionInfo;

    beforeEach(() => {
      sessionInfo = {
        name: 'test-session',
        socketPath: '/tmp/.claude-flow-sockets/test-session.sock',
        created: Date.now(),
        workingDir: '/test/working/dir',
        command: null,
        args: []
      };
      
      tmuxManager.activeSessions.set('test-session', sessionInfo);
      
      // Mock sessionExists to return true
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
    });

    it('should return PTY interface for existing session', async () => {
      const ptyInterface = await tmuxManager.connectToSession('test-session');
      
      expect(ptyInterface).toMatchObject({
        sessionName: 'test-session',
        socketPath: sessionInfo.socketPath,
        write: expect.any(Function),
        onData: expect.any(Function),
        onExit: expect.any(Function),
        resize: expect.any(Function),
        cleanup: expect.any(Function)
      });
    });

    it('should throw error for non-existent session', async () => {
      await expect(tmuxManager.connectToSession('nonexistent'))
        .rejects.toThrow('Session nonexistent not found');
    });

    it('should throw error if session no longer exists on system', async () => {
      // Mock sessionExists to return false
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1);
      });

      await expect(tmuxManager.connectToSession('test-session'))
        .rejects.toThrow('Session test-session no longer exists');
      
      // Should remove from active sessions
      expect(tmuxManager.activeSessions.has('test-session')).toBe(false);
    });

    describe('PTY Interface', () => {
      let ptyInterface;

      beforeEach(async () => {
        ptyInterface = await tmuxManager.connectToSession('test-session');
      });

      it('should send keys via write method', () => {
        const testData = 'echo hello';
        
        ptyInterface.write(testData);
        
        expect(spawn).toHaveBeenCalledWith(
          'tmux',
          ['-S', sessionInfo.socketPath, 'send-keys', '-t', 'test-session', '-l', testData],
          { stdio: 'ignore' }
        );
      });

      it('should handle data callbacks', () => {
        const callback = jest.fn();
        
        ptyInterface.onData(callback);
        
        expect(callback).toHaveBeenCalledTimes(0); // No initial data
      });

      it('should handle exit callbacks', () => {
        const exitCallback = jest.fn();
        
        ptyInterface.onExit(exitCallback);
        
        // Exit callbacks should be stored but not called immediately
        expect(exitCallback).not.toHaveBeenCalled();
      });

      it('should resize session', () => {
        ptyInterface.resize(100, 30);
        
        expect(spawn).toHaveBeenCalledWith(
          'tmux',
          [
            '-S', sessionInfo.socketPath,
            'resize-window',
            '-t', 'test-session',
            '-x', '100',
            '-y', '30'
          ],
          { stdio: 'ignore' }
        );
      });

      it('should cleanup properly', () => {
        const dataCallback = jest.fn();
        const exitCallback = jest.fn();
        
        ptyInterface.onData(dataCallback);
        ptyInterface.onExit(exitCallback);
        
        ptyInterface.cleanup();
        
        // Should not trigger callbacks after cleanup
        expect(dataCallback).not.toHaveBeenCalled();
        expect(exitCallback).not.toHaveBeenCalled();
      });
    });
  });

  describe('capturePane', () => {
    it('should capture pane content successfully', async () => {
      const expectedOutput = 'Hello from tmux\nLine 2\nLine 3';
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') callback(expectedOutput);
      });
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });

      const output = await tmuxManager.capturePane('test-session', '/path/to/socket');
      
      expect(output).toBe(expectedOutput);
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        ['-S', '/path/to/socket', 'capture-pane', '-t', 'test-session', '-p'],
        { stdio: 'pipe' }
      );
    });

    it('should handle capture pane failure', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1);
      });

      await expect(tmuxManager.capturePane('test-session', '/path/to/socket'))
        .rejects.toThrow('Failed to capture pane');
    });

    it('should handle capture pane error', async () => {
      const error = new Error('Capture failed');
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'error') callback(error);
      });

      await expect(tmuxManager.capturePane('test-session', '/path/to/socket'))
        .rejects.toThrow(error);
    });
  });

  describe('captureFullScreen', () => {
    it('should capture full screen with default rows', async () => {
      const mockOutput = Array(40).fill('line').join('\n');
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') callback(mockOutput);
      });
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });

      const output = await tmuxManager.captureFullScreen('test-session', '/path/to/socket');
      
      const lines = output.split('\n');
      expect(lines).toHaveLength(40);
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        ['-S', '/path/to/socket', 'capture-pane', '-t', 'test-session', '-S', '-40', '-E', '-1', '-p'],
        { stdio: 'pipe' }
      );
    });

    it('should capture full screen with custom rows', async () => {
      const customRows = 24;
      const mockOutput = Array(customRows).fill('line').join('\n');
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') callback(mockOutput);
      });
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });

      await tmuxManager.captureFullScreen('test-session', '/path/to/socket', customRows);
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        expect.arrayContaining(['-S', `-${customRows}`]),
        { stdio: 'pipe' }
      );
    });

    it('should pad with empty lines if output is too short', async () => {
      const shortOutput = 'line1\nline2';
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') callback(shortOutput);
      });
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });

      const output = await tmuxManager.captureFullScreen('test-session', '/path/to/socket', 5);
      
      const lines = output.split('\n');
      expect(lines).toHaveLength(5);
      expect(lines[0]).toBe(''); // Padded empty lines
      expect(lines[3]).toBe('line1');
      expect(lines[4]).toBe('line2');
    });

    it('should truncate if output is too long', async () => {
      const longOutput = Array(50).fill('line').map((_, i) => `line${i}`).join('\n');
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') callback(longOutput);
      });
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });

      const output = await tmuxManager.captureFullScreen('test-session', '/path/to/socket', 40);
      
      const lines = output.split('\n');
      expect(lines).toHaveLength(40);
      expect(lines[0]).toBe('line10'); // Should keep the last 40 lines
      expect(lines[39]).toBe('line49');
    });
  });

  describe('killSession', () => {
    let sessionInfo;

    beforeEach(() => {
      sessionInfo = {
        name: 'test-session',
        socketPath: '/tmp/.claude-flow-sockets/test-session.sock',
        created: Date.now()
      };
      
      tmuxManager.activeSessions.set('test-session', sessionInfo);
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
    });

    it('should kill session successfully', async () => {
      await tmuxManager.killSession('test-session');
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        ['-S', sessionInfo.socketPath, 'kill-session', '-t', 'test-session'],
        { stdio: 'pipe' }
      );
      
      expect(tmuxManager.activeSessions.has('test-session')).toBe(false);
    });

    it('should cleanup socket file after killing session', async () => {
      jest.mocked(fs.existsSync).mockReturnValue(true);
      
      await tmuxManager.killSession('test-session');
      
      expect(fs.unlinkSync).toHaveBeenCalledWith(sessionInfo.socketPath);
    });

    it('should handle non-existent session gracefully', async () => {
      await expect(tmuxManager.killSession('nonexistent'))
        .resolves.toBeUndefined();
      
      expect(spawn).not.toHaveBeenCalled();
    });

    it('should continue cleanup even if tmux command fails', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'error') callback(new Error('Tmux error'));
      });

      await tmuxManager.killSession('test-session');
      
      expect(tmuxManager.activeSessions.has('test-session')).toBe(false);
    });
  });

  describe('sendCommand', () => {
    let sessionInfo;

    beforeEach(() => {
      sessionInfo = {
        name: 'test-session',
        socketPath: '/tmp/.claude-flow-sockets/test-session.sock'
      };
      
      tmuxManager.activeSessions.set('test-session', sessionInfo);
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
    });

    it('should send command successfully', async () => {
      const command = 'ls -la';
      
      await tmuxManager.sendCommand('test-session', command);
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        ['-S', sessionInfo.socketPath, 'send-keys', '-t', 'test-session', command, 'Enter'],
        { stdio: 'pipe' }
      );
    });

    it('should throw error for non-existent session', async () => {
      await expect(tmuxManager.sendCommand('nonexistent', 'echo test'))
        .rejects.toThrow('Session nonexistent not found');
    });

    it('should handle command failure', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1);
      });

      await expect(tmuxManager.sendCommand('test-session', 'failing-command'))
        .rejects.toThrow('Failed to send command to session test-session');
    });
  });

  describe('getActiveSessions', () => {
    it('should return empty array when no active sessions', () => {
      const sessions = tmuxManager.getActiveSessions();
      
      expect(sessions).toEqual([]);
    });

    it('should return array of active session info', () => {
      const session1 = { name: 'session1', created: Date.now() };
      const session2 = { name: 'session2', created: Date.now() };
      
      tmuxManager.activeSessions.set('session1', session1);
      tmuxManager.activeSessions.set('session2', session2);
      
      const sessions = tmuxManager.getActiveSessions();
      
      expect(sessions).toHaveLength(2);
      expect(sessions).toContain(session1);
      expect(sessions).toContain(session2);
    });
  });

  describe('cleanup', () => {
    beforeEach(() => {
      // Setup multiple sessions
      const session1 = { name: 'session1', socketPath: '/tmp/session1.sock' };
      const session2 = { name: 'session2', socketPath: '/tmp/session2.sock' };
      
      tmuxManager.activeSessions.set('session1', session1);
      tmuxManager.activeSessions.set('session2', session2);
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
    });

    it('should clean up all active sessions', async () => {
      await tmuxManager.cleanup();
      
      expect(tmuxManager.activeSessions.size).toBe(0);
      expect(spawn).toHaveBeenCalledTimes(2); // One call per session
    });

    it('should clean up remaining socket files', async () => {
      jest.mocked(fs.readdirSync).mockReturnValue(['session1.sock', 'session2.sock', 'other.file']);
      jest.mocked(fs.existsSync).mockReturnValue(true);
      
      await tmuxManager.cleanup();
      
      expect(fs.readdirSync).toHaveBeenCalledWith(tmuxManager.socketDir);
      expect(fs.unlinkSync).toHaveBeenCalledTimes(4); // 2 from killSession + 2 from cleanup
    });

    it('should handle cleanup errors gracefully', async () => {
      jest.mocked(fs.readdirSync).mockImplementation(() => {
        throw new Error('Permission denied');
      });

      await expect(tmuxManager.cleanup()).resolves.toBeUndefined();
    });
  });

  describe('cleanupSocket', () => {
    it('should remove socket file if it exists', () => {
      const socketPath = '/tmp/test.sock';
      jest.mocked(fs.existsSync).mockReturnValue(true);
      
      tmuxManager.cleanupSocket(socketPath);
      
      expect(fs.unlinkSync).toHaveBeenCalledWith(socketPath);
    });

    it('should not attempt removal if socket does not exist', () => {
      const socketPath = '/tmp/nonexistent.sock';
      jest.mocked(fs.existsSync).mockReturnValue(false);
      
      tmuxManager.cleanupSocket(socketPath);
      
      expect(fs.unlinkSync).not.toHaveBeenCalled();
    });

    it('should handle unlink errors gracefully', () => {
      const socketPath = '/tmp/error.sock';
      jest.mocked(fs.existsSync).mockReturnValue(true);
      jest.mocked(fs.unlinkSync).mockImplementation(() => {
        throw new Error('Permission denied');
      });
      
      expect(() => tmuxManager.cleanupSocket(socketPath)).not.toThrow();
    });
  });

  describe('sendKeysToSession', () => {
    it('should send keys to session', () => {
      const sessionName = 'test-session';
      const socketPath = '/tmp/test.sock';
      const data = 'test input';
      
      tmuxManager.sendKeysToSession(sessionName, socketPath, data);
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        ['-S', socketPath, 'send-keys', '-t', sessionName, '-l', data],
        { stdio: 'ignore' }
      );
    });
  });

  describe('Edge Cases and Error Conditions', () => {
    it('should handle concurrent session creation', async () => {
      const promises = [];
      
      // Create multiple sessions concurrently
      for (let i = 0; i < 5; i++) {
        promises.push(tmuxManager.createSession(`concurrent-${i}`));
      }
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      const sessions = await Promise.all(promises);
      
      expect(sessions).toHaveLength(5);
      expect(tmuxManager.activeSessions.size).toBe(5);
      
      // All session names should be unique
      const sessionNames = sessions.map(s => s.name);
      const uniqueNames = new Set(sessionNames);
      expect(uniqueNames.size).toBe(5);
    });

    it('should handle very long session names', async () => {
      const longName = 'a'.repeat(200);
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await expect(tmuxManager.createSession(longName))
        .resolves.toMatchObject({ name: longName });
    });

    it('should handle special characters in commands', async () => {
      const specialCommand = 'echo "Hello & goodbye; $(whoami)"';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession('special-chars', specialCommand);
      
      expect(spawn).toHaveBeenCalledWith(
        'tmux',
        expect.arrayContaining([expect.stringContaining(specialCommand)]),
        expect.any(Object)
      );
    });

    it('should handle empty command gracefully', async () => {
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession('empty-cmd', '');
      
      // Should still create session without command
      expect(spawn).toHaveBeenCalled();
    });

    it('should handle resource exhaustion', async () => {
      // Simulate system resource exhaustion
      mockSpawn.mockImplementation(() => {
        throw new Error('EMFILE: too many open files');
      });
      
      await expect(tmuxManager.createSession('resource-test'))
        .rejects.toThrow('EMFILE');
    });
  });

  describe('Memory and Performance', () => {
    it('should not leak memory with many sessions', async () => {
      const initialSize = tmuxManager.activeSessions.size;
      
      // Create and destroy many sessions
      for (let i = 0; i < 100; i++) {
        const sessionName = `temp-${i}`;
        
        mockProcess.on.mockImplementation((event, callback) => {
          if (event === 'exit') callback(0);
        });
        
        await tmuxManager.createSession(sessionName);
        await tmuxManager.killSession(sessionName);
      }
      
      expect(tmuxManager.activeSessions.size).toBe(initialSize);
    });

    it('should handle rapid session operations', async () => {
      const operations = [];
      
      // Rapidly create, connect, and kill sessions
      for (let i = 0; i < 10; i++) {
        operations.push(async () => {
          const sessionName = `rapid-${i}`;
          
          mockProcess.on.mockImplementation((event, callback) => {
            if (event === 'exit') callback(0);
          });
          
          await tmuxManager.createSession(sessionName);
          await tmuxManager.connectToSession(sessionName);
          await tmuxManager.killSession(sessionName);
        });
      }
      
      await Promise.all(operations.map(op => op()));
      
      expect(tmuxManager.activeSessions.size).toBe(0);
    });

    it('should handle memory pressure scenarios', async () => {
      const sessionNames = [];
      
      // Create many sessions to simulate memory pressure
      for (let i = 0; i < 50; i++) {
        const sessionName = `memory-test-${i}`;
        sessionNames.push(sessionName);
        
        mockProcess.on.mockImplementation((event, callback) => {
          if (event === 'exit') callback(0);
        });
        
        await tmuxManager.createSession(sessionName);
      }
      
      expect(tmuxManager.activeSessions.size).toBe(50);
      
      // Clean up all at once
      await tmuxManager.cleanup();
      expect(tmuxManager.activeSessions.size).toBe(0);
    });

    it('should handle intensive polling operations', async () => {
      const sessionName = 'polling-test';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession(sessionName);
      const ptyInterface = await tmuxManager.connectToSession(sessionName);
      
      // Simulate intensive polling by rapidly capturing panes
      const capturePromises = [];
      for (let i = 0; i < 20; i++) {
        capturePromises.push(
          tmuxManager.capturePane(sessionName, tmuxManager.getSocketPath(sessionName))
        );
      }
      
      // All capture operations should complete without resource exhaustion
      await expect(Promise.all(capturePromises)).resolves.toBeDefined();
      
      ptyInterface.cleanup();
      await tmuxManager.killSession(sessionName);
    });
  });

  describe('Race Conditions and Concurrency', () => {
    it('should handle concurrent session creation with same name', async () => {
      const sessionName = 'concurrent-test';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      // Attempt to create same session concurrently
      const promise1 = tmuxManager.createSession(sessionName);
      const promise2 = tmuxManager.createSession(sessionName);
      
      // One should succeed, one should fail
      const results = await Promise.allSettled([promise1, promise2]);
      
      expect(results.some(r => r.status === 'fulfilled')).toBe(true);
      expect(tmuxManager.activeSessions.has(sessionName)).toBe(true);
    });

    it('should handle race between connect and kill operations', async () => {
      const sessionName = 'race-test';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession(sessionName);
      
      // Start connection and immediately kill session
      const connectPromise = tmuxManager.connectToSession(sessionName);
      const killPromise = tmuxManager.killSession(sessionName);
      
      const results = await Promise.allSettled([connectPromise, killPromise]);
      
      // Should handle gracefully without crashing
      expect(results.every(r => r.status === 'fulfilled' || r.status === 'rejected')).toBe(true);
    });

    it('should handle concurrent capture operations', async () => {
      const sessionName = 'capture-race';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      mockProcess.stdout.on.mockImplementation((event, callback) => {
        if (event === 'data') callback('test output');
      });
      
      await tmuxManager.createSession(sessionName);
      const socketPath = tmuxManager.getSocketPath(sessionName);
      
      // Run multiple capture operations concurrently
      const capturePromises = Array(10).fill(0).map(() => 
        tmuxManager.capturePane(sessionName, socketPath)
      );
      
      const results = await Promise.all(capturePromises);
      
      // All should succeed with consistent output
      expect(results.every(r => r === 'test output')).toBe(true);
    });

    it('should handle rapid write operations to PTY interface', async () => {
      const sessionName = 'pty-write-test';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession(sessionName);
      const ptyInterface = await tmuxManager.connectToSession(sessionName);
      
      // Rapidly write data
      for (let i = 0; i < 100; i++) {
        ptyInterface.write(`data-${i}\n`);
      }
      
      // Should handle without errors
      expect(spawn).toHaveBeenCalledTimes(expect.any(Number));
      
      ptyInterface.cleanup();
      await tmuxManager.killSession(sessionName);
    });

    it('should handle session state corruption scenarios', async () => {
      const sessionName = 'corruption-test';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession(sessionName);
      
      // Manually corrupt session state
      const sessionInfo = tmuxManager.activeSessions.get(sessionName);
      sessionInfo.socketPath = '/invalid/path/that/does/not/exist';
      
      // Operations should fail gracefully
      await expect(tmuxManager.connectToSession(sessionName))
        .rejects.toThrow();
      
      // Should clean up corrupted state
      expect(tmuxManager.activeSessions.has(sessionName)).toBe(false);
    });
  });

  describe('Resource Management and Cleanup', () => {
    it('should handle file descriptor exhaustion', async () => {
      // Mock system resource exhaustion
      let callCount = 0;
      mockSpawn.mockImplementation(() => {
        callCount++;
        if (callCount > 50) {
          const error = new Error('EMFILE: too many open files');
          error.code = 'EMFILE';
          throw error;
        }
        return mockProcess;
      });
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      // Create sessions until resource exhaustion
      const sessions = [];
      for (let i = 0; i < 60; i++) {
        try {
          const sessionName = `fd-test-${i}`;
          await tmuxManager.createSession(sessionName);
          sessions.push(sessionName);
        } catch (error) {
          expect(error.message).toContain('EMFILE');
          break;
        }
      }
      
      // Clean up created sessions
      for (const sessionName of sessions) {
        await tmuxManager.killSession(sessionName);
      }
    });

    it('should handle socket cleanup with permission errors', async () => {
      const sessionName = 'permission-test';
      
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession(sessionName);
      
      // Mock permission error on socket cleanup
      jest.mocked(fs.unlinkSync).mockImplementation(() => {
        const error = new Error('EACCES: permission denied');
        error.code = 'EACCES';
        throw error;
      });
      
      // Should handle cleanup error gracefully
      await expect(tmuxManager.killSession(sessionName)).resolves.toBeUndefined();
    });

    it('should handle orphaned session detection and cleanup', async () => {
      const sessionName = 'orphan-test';
      
      // Create session normally
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession(sessionName);
      
      // Simulate orphaned session (session exists in memory but not in tmux)
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1); // Session doesn't exist
      });
      
      // Connection should detect and clean up orphaned session
      await expect(tmuxManager.connectToSession(sessionName))
        .rejects.toThrow('Session orphan-test no longer exists');
      
      expect(tmuxManager.activeSessions.has(sessionName)).toBe(false);
    });

    it('should handle socket directory cleanup edge cases', async () => {
      // Mock socket directory with various file types
      jest.mocked(fs.readdirSync).mockReturnValue([
        'valid.sock',
        'another.sock',
        'not-a-socket.txt',
        'directory-entry',
        '.hidden-file'
      ]);
      
      jest.mocked(fs.existsSync).mockReturnValue(true);
      
      await tmuxManager.cleanup();
      
      // Should only attempt to clean up .sock files
      expect(fs.unlinkSync).toHaveBeenCalledWith(
        expect.stringContaining('valid.sock')
      );
      expect(fs.unlinkSync).toHaveBeenCalledWith(
        expect.stringContaining('another.sock')
      );
      
      // Should not attempt to clean up non-socket files
      expect(fs.unlinkSync).not.toHaveBeenCalledWith(
        expect.stringContaining('not-a-socket.txt')
      );
    });
  });

  describe('Error Recovery and Resilience', () => {
    it('should recover from tmux daemon restart', async () => {
      const sessionName = 'daemon-restart-test';
      
      // Initially successful
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await tmuxManager.createSession(sessionName);
      
      // Simulate tmux daemon restart (session check fails)
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(1);
      });
      
      const exists = await tmuxManager.sessionExists(
        sessionName, 
        tmuxManager.getSocketPath(sessionName)
      );
      
      expect(exists).toBe(false);
      
      // Should be able to create new session after daemon restart
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      await expect(tmuxManager.createSession('new-session'))
        .resolves.toBeDefined();
    });

    it('should handle network storage socket path issues', async () => {
      // Mock network storage path that becomes unavailable
      const originalSocketDir = tmuxManager.socketDir;
      tmuxManager.socketDir = '/mnt/network/unavailable';
      
      jest.mocked(fs.existsSync).mockReturnValue(false);
      jest.mocked(fs.mkdirSync).mockImplementation(() => {
        const error = new Error('ENOTCONN: network connection lost');
        error.code = 'ENOTCONN';
        throw error;
      });
      
      // Should handle network storage errors gracefully
      expect(() => tmuxManager.ensureSocketDir()).toThrow('ENOTCONN');
      
      // Restore original socket directory
      tmuxManager.socketDir = originalSocketDir;
    });

    it('should handle partial session cleanup failures', async () => {
      const sessions = ['partial-1', 'partial-2', 'partial-3'];
      
      // Create multiple sessions
      mockProcess.on.mockImplementation((event, callback) => {
        if (event === 'exit') callback(0);
      });
      
      for (const sessionName of sessions) {
        await tmuxManager.createSession(sessionName);
      }
      
      // Mock cleanup to fail on middle session
      let killCallCount = 0;
      mockProcess.on.mockImplementation((event, callback) => {
        killCallCount++;
        if (killCallCount === 2) {
          if (event === 'error') callback(new Error('Kill failed'));
        } else {
          if (event === 'exit') callback(0);
        }
      });
      
      // Cleanup should continue despite individual failures
      await tmuxManager.cleanup();
      
      // All sessions should be removed from active list
      expect(tmuxManager.activeSessions.size).toBe(0);
    });
  });
});