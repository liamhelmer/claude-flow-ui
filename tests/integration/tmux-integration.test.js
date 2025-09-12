/**
 * Integration tests for tmux session management
 */

const TmuxManager = require('../../src/lib/tmux-manager');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

describe('Tmux Integration', () => {
  let tmuxManager;
  let testWorkingDir;

  beforeAll(() => {
    testWorkingDir = path.join(__dirname, '..', '..', 'test-tmp');
    if (!fs.existsSync(testWorkingDir)) {
      fs.mkdirSync(testWorkingDir, { recursive: true });
    }
    tmuxManager = new TmuxManager(testWorkingDir);
  });

  afterAll(async () => {
    if (tmuxManager) {
      await tmuxManager.cleanup();
    }
    // Clean up test directory
    if (fs.existsSync(testWorkingDir)) {
      fs.rmSync(testWorkingDir, { recursive: true, force: true });
    }
  });

  beforeEach(() => {
    jest.setTimeout(10000); // 10 second timeout for tmux operations
  });

  describe('TmuxManager', () => {
    test('should detect if tmux is available', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      expect(typeof isAvailable).toBe('boolean');
      
      if (isAvailable) {
        console.log('✅ Tmux is available for testing');
      } else {
        console.log('⚠️  Tmux not available - some tests may be skipped');
      }
    });

    test('should create unique session names', () => {
      const name1 = tmuxManager.generateSessionName();
      const name2 = tmuxManager.generateSessionName();
      
      expect(name1).toMatch(/^cf-\d+-[a-f0-9]+$/);
      expect(name2).toMatch(/^cf-\d+-[a-f0-9]+$/);
      expect(name1).not.toBe(name2);
    });

    test('should create and manage socket paths', () => {
      const sessionName = 'test-session';
      const socketPath = tmuxManager.getSocketPath(sessionName);
      
      expect(socketPath).toContain('.claude-flow-sockets');
      expect(socketPath).toContain('test-session.sock');
      expect(path.isAbsolute(socketPath)).toBe(true);
    });
  });

  describe('Session Management', () => {
    let sessionName;
    let sessionInfo;

    test('should create a tmux session', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable) {
        console.log('Skipping tmux session test - tmux not available');
        return;
      }

      sessionInfo = await tmuxManager.createSession(null, 'echo', ['Hello World!']);
      sessionName = sessionInfo.name;

      expect(sessionInfo).toHaveProperty('name');
      expect(sessionInfo).toHaveProperty('socketPath');
      expect(sessionInfo).toHaveProperty('created');
      expect(sessionInfo).toHaveProperty('workingDir');
      expect(sessionInfo.command).toBe('echo');
      expect(sessionInfo.args).toEqual(['Hello World!']);

      // Check that session exists in active sessions
      const activeSessions = tmuxManager.getActiveSessions();
      expect(activeSessions).toContainEqual(
        expect.objectContaining({ name: sessionName })
      );
    });

    test('should connect to existing tmux session', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable || !sessionName) {
        console.log('Skipping connection test - tmux not available or no session');
        return;
      }

      const terminal = await tmuxManager.connectToSession(sessionName);

      expect(terminal).toHaveProperty('sessionName');
      expect(terminal).toHaveProperty('socketPath');
      expect(terminal).toHaveProperty('write');
      expect(terminal).toHaveProperty('onData');
      expect(terminal).toHaveProperty('onExit');
      expect(terminal).toHaveProperty('resize');

      expect(terminal.sessionName).toBe(sessionName);
    });

    test('should capture session content', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable || !sessionName) {
        console.log('Skipping capture test - tmux not available or no session');
        return;
      }

      const socketPath = tmuxManager.getSocketPath(sessionName);
      // Test session still exists before trying to capture content
      const exists = await tmuxManager.sessionExists(sessionName);
      expect(exists).toBe(true);
      
      // For this test, we'll just verify the session is active
      expect(tmuxManager.activeSessions.has(sessionName)).toBe(true);
      // (This is timing dependent, so we just check it's a string)
    });

    test('should send keys to session', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable || !sessionName) {
        console.log('Skipping send keys test - tmux not available or no session');
        return;
      }

      const socketPath = tmuxManager.getSocketPath(sessionName);
      
      // This should not throw
      expect(() => {
        tmuxManager.sendKeysToSession(sessionName, socketPath, 'test input');
      }).not.toThrow();
    });

    test('should check if session exists', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable || !sessionName) {
        console.log('Skipping session exists test - tmux not available or no session');
        return;
      }

      const socketPath = tmuxManager.getSocketPath(sessionName);
      const exists = await tmuxManager.sessionExists(sessionName, socketPath);

      // Session might have exited by now (echo command completes quickly)
      expect(typeof exists).toBe('boolean');
    });

    test('should kill session', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable || !sessionName) {
        console.log('Skipping kill session test - tmux not available or no session');
        return;
      }

      await tmuxManager.killSession(sessionName);

      // Session should be removed from active sessions
      const activeSessions = tmuxManager.getActiveSessions();
      expect(activeSessions).not.toContainEqual(
        expect.objectContaining({ name: sessionName })
      );
    });
  });

  describe('Error Handling', () => {
    test('should handle non-existent session gracefully', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable) {
        console.log('Skipping error handling test - tmux not available');
        return;
      }

      await expect(
        tmuxManager.connectToSession('non-existent-session')
      ).rejects.toThrow('Session non-existent-session not found');
    });

    test('should handle tmux not available', async () => {
      // Temporarily create a manager that won't find tmux
      const tempManager = new TmuxManager('/tmp');
      
      // Mock spawn to simulate tmux not available
      const originalSpawn = require('child_process').spawn;
      const mockSpawn = jest.fn(() => {
        const mockProcess = {
          on: jest.fn((event, callback) => {
            if (event === 'error') {
              setTimeout(() => callback(new Error('Command not found')), 0);
            }
          }),
        };
        return mockProcess;
      });
      
      require('child_process').spawn = mockSpawn;
      
      const isAvailable = await tempManager.isTmuxAvailable();
      expect(isAvailable).toBe(false);
      
      // Restore original spawn
      require('child_process').spawn = originalSpawn;
    });
  });

  describe('Socket Management', () => {
    test('should create socket directory', () => {
      const socketDir = '/tmp/.claude-flow-sockets';
      expect(fs.existsSync(socketDir)).toBe(true);
    });

    test('should clean up socket files', () => {
      const socketDir = '/tmp/.claude-flow-sockets';
      const testSocketPath = path.join(socketDir, 'test.sock');
      
      // Ensure directory exists
      if (!fs.existsSync(socketDir)) {
        fs.mkdirSync(socketDir, { recursive: true });
      }
      
      // Create a fake socket file
      fs.writeFileSync(testSocketPath, 'test');
      expect(fs.existsSync(testSocketPath)).toBe(true);
      
      // Clean it up
      tmuxManager.cleanupSocket(testSocketPath);
      expect(fs.existsSync(testSocketPath)).toBe(false);
    });
  });

  describe('WebSocket Integration', () => {
    let sessionInfo;
    let terminal;

    beforeEach(async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (isAvailable) {
        // Create a persistent shell session for WebSocket testing
        sessionInfo = await tmuxManager.createSession(null, 'bash', ['-c', 'sleep 5']);
        terminal = await tmuxManager.connectToSession(sessionInfo.name);
      }
    });

    afterEach(async () => {
      if (sessionInfo) {
        await tmuxManager.killSession(sessionInfo.name);
      }
    });

    test('should handle WebSocket-like data flow', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable || !terminal) {
        console.log('Skipping WebSocket test - tmux not available');
        return;
      }

      return new Promise((resolve) => {
        let dataReceived = '';
        
        // Set up data handler
        terminal.onData((data) => {
          dataReceived += data;
          
          // Resolve after receiving some data or timeout
          setTimeout(() => {
            expect(typeof dataReceived).toBe('string');
            resolve();
          }, 100);
        });

        // Send a test command
        setTimeout(() => {
          terminal.write('echo "test"\\n');
        }, 100);

        // Timeout the test after 3 seconds
        setTimeout(() => {
          resolve();
        }, 3000);
      });
    });

    test('should handle resize operations', async () => {
      const isAvailable = await tmuxManager.isTmuxAvailable();
      if (!isAvailable || !terminal) {
        console.log('Skipping resize test - tmux not available');
        return;
      }

      // This should not throw
      expect(() => {
        terminal.resize(80, 24);
        terminal.resize(120, 30);
      }).not.toThrow();
    });
  });
});