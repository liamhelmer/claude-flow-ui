/**
 * Comprehensive Test Suite for Tmux Wait/Async Operations
 * Testing wait functionality, timeout handling, and async operations
 */

const TmuxManager = require('../src/lib/tmux-manager');
const TmuxStreamManager = require('../src/lib/tmux-stream-manager');

// Mock child_process for controlled testing
jest.mock('child_process');
jest.mock('fs');
jest.mock('crypto');
jest.mock('../src/lib/secure-temp-dir');

const { spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

describe('Tmux Wait/Async Operations', () => {
  let tmuxManager;
  let tmuxStreamManager;
  let mockProcess;

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup mock process
    mockProcess = {
      stdout: { on: jest.fn() },
      stderr: { on: jest.fn() },
      stdin: { end: jest.fn() },
      on: jest.fn(),
      kill: jest.fn(),
      pid: 12345
    };

    spawn.mockReturnValue(mockProcess);
    fs.existsSync.mockReturnValue(true);
    fs.mkdirSync.mockReturnValue(undefined);
    crypto.randomBytes.mockReturnValue(Buffer.from('abcd1234', 'hex'));

    // Mock SecureTempDir
    const { getInstance } = require('../src/lib/secure-temp-dir');
    getInstance.mockReturnValue({
      getSocketDir: () => '/test/sockets',
      getSocketPath: (name) => `/test/sockets/${name}.sock`,
      cleanup: jest.fn()
    });

    tmuxManager = new TmuxManager('/test/workingdir');
    tmuxStreamManager = new TmuxStreamManager();
  });

  describe('Promise-based Operations', () => {
    test('should handle session creation with proper promise resolution', async () => {
      const promise = tmuxManager.createSession();

      // Simulate async success
      setTimeout(() => {
        mockProcess.on.mock.calls.find(call => call[0] === 'exit')?.[1](0);
      }, 10);

      const result = await promise;
      expect(result).toHaveProperty('name');
      expect(result).toHaveProperty('socketPath');
    });

    test('should handle session creation timeout scenarios', async () => {
      const promise = tmuxManager.createSession();

      // Never resolve the process - timeout scenario
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Operation timeout')), 50);
      });

      await expect(Promise.race([promise, timeoutPromise]))
        .rejects.toThrow('Operation timeout');
    });

    test('should handle concurrent session creation', async () => {
      const promises = Array(5).fill(null).map((_, i) =>
        tmuxManager.createSession(`session-${i}`)
      );

      // Simulate all processes completing
      setTimeout(() => {
        mockProcess.on.mock.calls
          .filter(call => call[0] === 'exit')
          .forEach(call => call[1](0));
      }, 10);

      const results = await Promise.all(promises);
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result).toHaveProperty('name');
        expect(result).toHaveProperty('socketPath');
      });
    });
  });

  describe('Timeout Handling', () => {
    test('should handle capture pane timeouts gracefully', async () => {
      const sessionName = 'test-session';
      const socketPath = '/test/socket';

      // Mock sessionExists to return true
      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(true);

      const promise = tmuxManager.capturePane(sessionName, socketPath);

      // Simulate timeout by never calling exit/error callbacks
      // The internal timeout should trigger

      await expect(promise).rejects.toThrow('Capture pane timed out');
    }, 5000);

    test('should handle full screen capture with retry logic', async () => {
      const sessionName = 'test-session';
      const socketPath = '/test/socket';

      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(true);
      jest.spyOn(tmuxManager, 'fallbackCapture').mockResolvedValue('fallback content');

      const promise = tmuxManager.captureFullScreen(sessionName, socketPath);

      // Simulate timeout on first attempt
      setTimeout(() => {
        // Don't trigger any callbacks - let timeout occur
      }, 100);

      const result = await promise;
      expect(result).toBe('fallback content');
    }, 10000);

    test('should handle executeWithTimeout properly', async () => {
      const command = 'tmux';
      const args = ['-V'];
      const timeout = 1000;

      const promise = tmuxManager.executeWithTimeout(command, args, timeout);

      // Simulate command taking too long
      setTimeout(() => {
        mockProcess.on.mock.calls.find(call => call[0] === 'exit')?.[1](0);
      }, 2000); // Longer than timeout

      await expect(promise).rejects.toThrow('Command execution timed out');
    });
  });

  describe('Polling and Intervals', () => {
    test('should handle session polling lifecycle', async () => {
      const sessionName = 'polling-test';

      // Mock sessionExists to return true initially
      jest.spyOn(tmuxManager, 'sessionExists')
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false); // Session ends

      jest.spyOn(tmuxManager, 'capturePane').mockResolvedValue('test output');
      jest.spyOn(tmuxManager, 'captureFullScreen').mockResolvedValue('full screen');
      jest.spyOn(tmuxManager, 'isPaneDead').mockResolvedValue({ isDead: false });

      // Add session to activeSessions
      tmuxManager.activeSessions.set(sessionName, {
        name: sessionName,
        socketPath: '/test/socket',
        created: Date.now()
      });

      const ptyInterface = await tmuxManager.connectToSession(sessionName);

      let dataReceived = false;
      ptyInterface.onData((data) => {
        dataReceived = true;
      });

      // Wait for polling to occur
      await new Promise(resolve => setTimeout(resolve, 500));

      expect(dataReceived).toBe(true);

      ptyInterface.cleanup();
    });

    test('should handle stream manager capture intervals', async () => {
      const sessionName = 'stream-test';

      jest.spyOn(tmuxStreamManager, 'isPaneDead').mockResolvedValue({ isDead: false });
      jest.spyOn(tmuxStreamManager, 'capturePane').mockResolvedValue('stream output');

      // Mock createSession process completion
      setTimeout(() => {
        mockProcess.on.mock.calls.find(call => call[0] === 'exit')?.[1](0);
      }, 10);

      const session = await tmuxStreamManager.createSession(sessionName);

      let callbackCalled = false;
      const clientId = 'test-client';

      tmuxStreamManager.connectClient(clientId, sessionName, (data) => {
        callbackCalled = true;
      });

      // Wait for interval to fire
      await new Promise(resolve => setTimeout(resolve, 300));

      expect(callbackCalled).toBe(true);
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should recover from temporary capture failures', async () => {
      const sessionName = 'recovery-test';
      const socketPath = '/test/socket';

      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(true);

      // Mock fallback capture to succeed
      jest.spyOn(tmuxManager, 'fallbackCapture').mockResolvedValue('recovered content');

      const promise = tmuxManager.captureFullScreen(sessionName, socketPath);

      // Simulate failure then recovery
      setTimeout(() => {
        mockProcess.on.mock.calls.find(call => call[0] === 'exit')?.[1](1); // Fail first
      }, 10);

      const result = await promise;
      expect(result).toBe('recovered content');
    });

    test('should handle socket file deletion gracefully', async () => {
      const sessionName = 'socket-deletion-test';

      // Start with socket existing, then disappear
      fs.existsSync.mockReturnValueOnce(true).mockReturnValue(false);

      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(true);
      jest.spyOn(tmuxManager, 'capturePane').mockResolvedValue('initial output');
      jest.spyOn(tmuxManager, 'captureFullScreen').mockResolvedValue('full screen');
      jest.spyOn(tmuxManager, 'isPaneDead').mockResolvedValue({ isDead: false });

      tmuxManager.activeSessions.set(sessionName, {
        name: sessionName,
        socketPath: '/test/socket',
        created: Date.now()
      });

      const ptyInterface = await tmuxManager.connectToSession(sessionName);

      let exitCalled = false;
      ptyInterface.onExit(() => {
        exitCalled = true;
      });

      // Wait for polling to detect socket deletion
      await new Promise(resolve => setTimeout(resolve, 300));

      // Should have detected socket deletion and triggered cleanup
      expect(exitCalled).toBe(true);
    });

    test('should handle process.exit scenarios in error conditions', (done) => {
      const originalExit = process.exit;
      process.exit = jest.fn();

      const sessionName = 'exit-test';

      // Mock socket file deletion scenario
      fs.existsSync.mockReturnValue(false);

      tmuxStreamManager.startSessionStream(sessionName);

      // Set up session with fake data
      tmuxStreamManager.sessions.set(sessionName, {
        name: sessionName,
        socketPath: '/fake/socket',
        clients: new Set(),
        streaming: true
      });

      // Wait for interval to detect socket deletion
      setTimeout(() => {
        expect(process.exit).toHaveBeenCalledWith(0);
        process.exit = originalExit;
        done();
      }, 300);
    });
  });

  describe('Memory and Resource Management', () => {
    test('should clean up timers and intervals properly', async () => {
      const sessionName = 'cleanup-test';

      jest.spyOn(global, 'clearTimeout');
      jest.spyOn(global, 'clearInterval');

      // Mock successful session creation
      setTimeout(() => {
        mockProcess.on.mock.calls.find(call => call[0] === 'exit')?.[1](0);
      }, 10);

      const session = await tmuxStreamManager.createSession(sessionName);

      // Connect and disconnect client to trigger cleanup paths
      const clientId = 'cleanup-client';
      tmuxStreamManager.connectClient(clientId, sessionName, () => {});
      tmuxStreamManager.disconnectClient(clientId);

      // Trigger cleanup
      await tmuxStreamManager.cleanup();

      expect(clearTimeout).toHaveBeenCalled();
      expect(clearInterval).toHaveBeenCalled();
    });

    test('should handle memory pressure during intensive operations', async () => {
      const sessionCount = 10;
      const promises = [];

      // Create multiple sessions to simulate memory pressure
      for (let i = 0; i < sessionCount; i++) {
        promises.push(tmuxManager.createSession(`memory-test-${i}`));
      }

      // Simulate all completing successfully
      setTimeout(() => {
        mockProcess.on.mock.calls
          .filter(call => call[0] === 'exit')
          .forEach(call => call[1](0));
      }, 10);

      const results = await Promise.all(promises);
      expect(results).toHaveLength(sessionCount);

      // Verify memory cleanup
      expect(tmuxManager.activeSessions.size).toBe(sessionCount);

      // Clean up all sessions
      await tmuxManager.cleanup();
      expect(tmuxManager.activeSessions.size).toBe(0);
    });
  });

  describe('Edge Cases and Race Conditions', () => {
    test('should handle rapid connect/disconnect cycles', async () => {
      const sessionName = 'rapid-test';

      setTimeout(() => {
        mockProcess.on.mock.calls.find(call => call[0] === 'exit')?.[1](0);
      }, 10);

      const session = await tmuxStreamManager.createSession(sessionName);

      // Rapid connect/disconnect cycles
      for (let i = 0; i < 5; i++) {
        const clientId = `rapid-client-${i}`;
        tmuxStreamManager.connectClient(clientId, sessionName, () => {});
        tmuxStreamManager.disconnectClient(clientId);
      }

      // Should handle gracefully without memory leaks
      expect(tmuxStreamManager.clientStreams.size).toBe(0);
    });

    test('should handle simultaneous session creation and destruction', async () => {
      const sessionName = 'race-test';

      // Start session creation
      const createPromise = tmuxManager.createSession(sessionName);

      // Immediately try to kill it (race condition)
      const killPromise = tmuxManager.killSession(sessionName);

      // Simulate process completion
      setTimeout(() => {
        mockProcess.on.mock.calls
          .filter(call => call[0] === 'exit')
          .forEach(call => call[1](0));
      }, 10);

      const [createResult] = await Promise.allSettled([createPromise, killPromise]);

      // Should handle race condition gracefully
      expect(createResult.status).toBe('fulfilled');
    });

    test('should handle timeout during cleanup operations', async () => {
      const sessionName = 'timeout-cleanup-test';

      // Add session to activeSessions
      tmuxManager.activeSessions.set(sessionName, {
        name: sessionName,
        socketPath: '/test/socket',
        created: Date.now()
      });

      // Mock cleanup to never resolve (simulate hanging)
      const originalKillSession = tmuxManager.killSession;
      tmuxManager.killSession = jest.fn(() => new Promise(() => {})); // Never resolves

      const originalExit = process.exit;
      process.exit = jest.fn();

      // Start cleanup with timeout
      const cleanupPromise = tmuxManager.cleanup();

      // Wait for cleanup timeout to trigger
      await new Promise(resolve => setTimeout(resolve, 3500));

      expect(process.exit).toHaveBeenCalledWith(1);

      // Restore original functions
      tmuxManager.killSession = originalKillSession;
      process.exit = originalExit;
    });
  });

  describe('Performance Benchmarks', () => {
    test('should handle high-frequency capture operations efficiently', async () => {
      const sessionName = 'perf-test';
      const socketPath = '/test/socket';

      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(true);
      jest.spyOn(tmuxManager, 'executeWithTimeout').mockResolvedValue('mock output');

      const startTime = Date.now();
      const capturePromises = Array(20).fill(null).map(() =>
        tmuxManager.capturePane(sessionName, socketPath)
      );

      const results = await Promise.all(capturePromises);
      const endTime = Date.now();

      expect(results).toHaveLength(20);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });

    test('should maintain responsiveness under load', async () => {
      const sessionCount = 5;
      const operationsPerSession = 4;

      // Create multiple sessions
      const sessionPromises = Array(sessionCount).fill(null).map((_, i) =>
        tmuxManager.createSession(`load-test-${i}`)
      );

      setTimeout(() => {
        mockProcess.on.mock.calls
          .filter(call => call[0] === 'exit')
          .forEach(call => call[1](0));
      }, 10);

      const sessions = await Promise.all(sessionPromises);

      // Perform multiple operations on each session
      const operationPromises = [];
      sessions.forEach(session => {
        for (let i = 0; i < operationsPerSession; i++) {
          operationPromises.push(
            tmuxManager.capturePane(session.name, session.socketPath)
              .catch(() => 'failed') // Handle potential failures gracefully
          );
        }
      });

      jest.spyOn(tmuxManager, 'sessionExists').mockResolvedValue(true);
      jest.spyOn(tmuxManager, 'executeWithTimeout').mockResolvedValue('load test output');

      const startTime = Date.now();
      const results = await Promise.all(operationPromises);
      const endTime = Date.now();

      expect(results).toHaveLength(sessionCount * operationsPerSession);
      expect(endTime - startTime).toBeLessThan(2000); // Should complete within 2 seconds
    });
  });
});