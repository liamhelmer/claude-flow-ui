/**
 * Tmux Session Management Integration Tests
 * Tests tmux session lifecycle, window management, and pane operations
 */

import TmuxSessionManager, { TmuxSession, TmuxWindow } from '@/lib/tmux/session-manager';
import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';

// Mock child_process for tmux operations
jest.mock('child_process', () => ({
  spawn: jest.fn(),
  exec: jest.fn(),
  execSync: jest.fn()
}));

const mockSpawn = spawn as jest.MockedFunction<typeof spawn>;

describe('Tmux Session Management Integration', () => {
  let sessionManager: TmuxSessionManager;
  let mockTmuxProcess: ChildProcess & EventEmitter;

  beforeAll(() => {
    // Setup mock tmux process
    mockTmuxProcess = new EventEmitter() as ChildProcess & EventEmitter;
    mockTmuxProcess.stdout = new EventEmitter() as any;
    mockTmuxProcess.stderr = new EventEmitter() as any;
    mockTmuxProcess.stdin = { write: jest.fn(), end: jest.fn() } as any;
    mockTmuxProcess.pid = 12345;
    mockTmuxProcess.kill = jest.fn();

    mockSpawn.mockReturnValue(mockTmuxProcess);
  });

  beforeEach(() => {
    sessionManager = new TmuxSessionManager();
    jest.clearAllMocks();
  });

  afterEach(() => {
    sessionManager.cleanup();
  });

  describe('Session Creation and Management', () => {
    it('should create a new tmux session', async () => {
      const session = await sessionManager.createSession('test-session');

      expect(session).toBeDefined();
      expect(session.name).toBe('test-session');
      expect(session.status).toBe('active');
      expect(session.windowCount).toBe(1);
      expect(session.created).toBeInstanceOf(Date);
    });

    it('should auto-generate session names when not provided', async () => {
      const session1 = await sessionManager.createSession();
      const session2 = await sessionManager.createSession();

      expect(session1.name).toContain('terminal_1');
      expect(session2.name).toContain('terminal_2');
      expect(session1.id).not.toBe(session2.id);
    });

    it('should track multiple sessions', async () => {
      const session1 = await sessionManager.createSession('session-1');
      const session2 = await sessionManager.createSession('session-2');
      const session3 = await sessionManager.createSession('session-3');

      const sessions = sessionManager.listSessions();
      expect(sessions).toHaveLength(3);
      expect(sessions.map(s => s.name)).toEqual(['session-1', 'session-2', 'session-3']);
    });

    it('should retrieve sessions by ID', async () => {
      const createdSession = await sessionManager.createSession('findable-session');
      const foundSession = sessionManager.getSession(createdSession.id);

      expect(foundSession).toBeDefined();
      expect(foundSession?.id).toBe(createdSession.id);
      expect(foundSession?.name).toBe('findable-session');
    });

    it('should return null for non-existent session IDs', () => {
      const session = sessionManager.getSession('non-existent-id');
      expect(session).toBeNull();
    });

    it('should destroy sessions and clean up resources', async () => {
      const session = await sessionManager.createSession('destroyable-session');
      const sessionId = session.id;

      expect(sessionManager.getSession(sessionId)).not.toBeNull();

      const destroyed = await sessionManager.destroySession(sessionId);
      expect(destroyed).toBe(true);
      expect(sessionManager.getSession(sessionId)).toBeNull();
    });

    it('should handle destruction of non-existent sessions', async () => {
      const result = await sessionManager.destroySession('non-existent-id');
      expect(result).toBe(false);
    });
  });

  describe('Window Management', () => {
    let testSession: TmuxSession;

    beforeEach(async () => {
      testSession = await sessionManager.createSession('window-test-session');
    });

    it('should create windows within sessions', async () => {
      const window = await sessionManager.createWindow(testSession.id, 'test-window');

      expect(window).toBeDefined();
      expect(window?.sessionId).toBe(testSession.id);
      expect(window?.name).toBe('test-window');
      expect(window?.isActive).toBe(true);
      expect(window?.panes).toEqual([]);
    });

    it('should auto-generate window names', async () => {
      const window1 = await sessionManager.createWindow(testSession.id);
      const window2 = await sessionManager.createWindow(testSession.id);

      expect(window1?.name).toContain('window_2'); // Session starts with 1 window
      expect(window2?.name).toContain('window_3');
    });

    it('should increment window count in session', async () => {
      const initialCount = testSession.windowCount;

      await sessionManager.createWindow(testSession.id, 'window-1');
      await sessionManager.createWindow(testSession.id, 'window-2');

      const updatedSession = sessionManager.getSession(testSession.id);
      expect(updatedSession?.windowCount).toBe(initialCount + 2);
    });

    it('should handle window creation for non-existent sessions', async () => {
      const window = await sessionManager.createWindow('non-existent-session', 'test-window');
      expect(window).toBeNull();
    });
  });

  describe('Command Execution', () => {
    let testSession: TmuxSession;

    beforeEach(async () => {
      testSession = await sessionManager.createSession('command-test-session');
    });

    it('should send commands to sessions', async () => {
      const result = await sessionManager.sendCommand(testSession.id, 'echo "Hello World"');
      expect(result).toBe(true);

      const updatedSession = sessionManager.getSession(testSession.id);
      expect(updatedSession?.lastActivity).toBeInstanceOf(Date);
    });

    it('should update session activity on command execution', async () => {
      const originalActivity = testSession.lastActivity;

      // Wait a bit to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));

      await sessionManager.sendCommand(testSession.id, 'ls');

      const updatedSession = sessionManager.getSession(testSession.id);
      expect(updatedSession?.lastActivity.getTime()).toBeGreaterThan(originalActivity.getTime());
    });

    it('should handle commands for non-existent sessions', async () => {
      const result = await sessionManager.sendCommand('non-existent-session', 'command');
      expect(result).toBe(false);
    });

    it('should handle complex commands with special characters', async () => {
      const commands = [
        'echo "Hello World"',
        'ls -la | grep test',
        'cd /tmp && touch test.txt',
        'export VAR="value with spaces"'
      ];

      for (const command of commands) {
        const result = await sessionManager.sendCommand(testSession.id, command);
        expect(result).toBe(true);
      }
    });
  });

  describe('Session Resizing', () => {
    let testSession: TmuxSession;

    beforeEach(async () => {
      testSession = await sessionManager.createSession('resize-test-session');
    });

    it('should resize sessions', async () => {
      const result = await sessionManager.resizeSession(testSession.id, 120, 40);
      expect(result).toBe(true);
    });

    it('should handle various terminal sizes', async () => {
      const sizes = [
        { width: 80, height: 24 },
        { width: 120, height: 40 },
        { width: 200, height: 60 },
        { width: 40, height: 10 }
      ];

      for (const size of sizes) {
        const result = await sessionManager.resizeSession(testSession.id, size.width, size.height);
        expect(result).toBe(true);
      }
    });

    it('should handle resize for non-existent sessions', async () => {
      const result = await sessionManager.resizeSession('non-existent-session', 80, 24);
      expect(result).toBe(false);
    });
  });

  describe('Session Status and Monitoring', () => {
    let testSession: TmuxSession;

    beforeEach(async () => {
      testSession = await sessionManager.createSession('status-test-session');
    });

    it('should get session status', () => {
      const status = sessionManager.getSessionStatus(testSession.id);
      expect(status).toBe('active');
    });

    it('should return null for non-existent session status', () => {
      const status = sessionManager.getSessionStatus('non-existent-session');
      expect(status).toBeNull();
    });

    it('should update activity timestamps', () => {
      const originalActivity = sessionManager.getSession(testSession.id)?.lastActivity;

      sessionManager.updateActivity(testSession.id);

      const updatedActivity = sessionManager.getSession(testSession.id)?.lastActivity;
      expect(updatedActivity?.getTime()).toBeGreaterThan(originalActivity?.getTime() || 0);
    });

    it('should handle activity update for non-existent sessions', () => {
      expect(() => {
        sessionManager.updateActivity('non-existent-session');
      }).not.toThrow();
    });
  });

  describe('Event System Integration', () => {
    it('should emit session creation events', (done) => {
      sessionManager.on('session:created', (session: TmuxSession) => {
        expect(session.name).toBe('event-test-session');
        expect(session.status).toBe('active');
        done();
      });

      sessionManager.createSession('event-test-session');
    });

    it('should emit session destruction events', (done) => {
      sessionManager.createSession('destroyable-session').then((session) => {
        sessionManager.on('session:destroyed', (destroyedSession: TmuxSession) => {
          expect(destroyedSession.id).toBe(session.id);
          done();
        });

        sessionManager.destroySession(session.id);
      });
    });

    it('should emit window creation events', (done) => {
      sessionManager.createSession('window-event-test').then((session) => {
        sessionManager.on('window:created', (window: TmuxWindow) => {
          expect(window.sessionId).toBe(session.id);
          expect(window.name).toBe('test-window');
          done();
        });

        sessionManager.createWindow(session.id, 'test-window');
      });
    });

    it('should emit command execution events', (done) => {
      sessionManager.createSession('command-event-test').then((session) => {
        sessionManager.on('command:sent', (data: any) => {
          expect(data.sessionId).toBe(session.id);
          expect(data.command).toBe('echo test');
          done();
        });

        sessionManager.sendCommand(session.id, 'echo test');
      });
    });

    it('should emit resize events', (done) => {
      sessionManager.createSession('resize-event-test').then((session) => {
        sessionManager.on('session:resized', (data: any) => {
          expect(data.sessionId).toBe(session.id);
          expect(data.width).toBe(100);
          expect(data.height).toBe(30);
          done();
        });

        sessionManager.resizeSession(session.id, 100, 30);
      });
    });

    it('should emit activity update events', (done) => {
      sessionManager.createSession('activity-event-test').then((session) => {
        sessionManager.on('activity:updated', (data: any) => {
          expect(data.sessionId).toBe(session.id);
          expect(data.timestamp).toBeInstanceOf(Date);
          done();
        });

        sessionManager.updateActivity(session.id);
      });
    });

    it('should handle multiple event listeners', () => {
      const listener1 = jest.fn();
      const listener2 = jest.fn();
      const listener3 = jest.fn();

      sessionManager.on('test-event', listener1);
      sessionManager.on('test-event', listener2);
      sessionManager.on('test-event', listener3);

      // Emit test event
      (sessionManager as any).emit('test-event', { data: 'test' });

      expect(listener1).toHaveBeenCalledWith({ data: 'test' });
      expect(listener2).toHaveBeenCalledWith({ data: 'test' });
      expect(listener3).toHaveBeenCalledWith({ data: 'test' });
    });

    it('should remove event listeners', () => {
      const listener = jest.fn();

      sessionManager.on('removable-event', listener);
      sessionManager.off('removable-event', listener);

      // Emit event - listener should not be called
      (sessionManager as any).emit('removable-event', { data: 'test' });

      expect(listener).not.toHaveBeenCalled();
    });
  });

  describe('Session Persistence and Recovery', () => {
    it('should maintain session state across operations', async () => {
      const session = await sessionManager.createSession('persistent-session');
      const originalId = session.id;

      // Perform various operations
      await sessionManager.sendCommand(session.id, 'echo test');
      await sessionManager.createWindow(session.id, 'test-window');
      await sessionManager.resizeSession(session.id, 120, 40);

      // Session should still exist and maintain state
      const persistentSession = sessionManager.getSession(originalId);
      expect(persistentSession).not.toBeNull();
      expect(persistentSession?.id).toBe(originalId);
      expect(persistentSession?.windowCount).toBe(2); // Original + created window
    });

    it('should handle concurrent session operations', async () => {
      const sessions = await Promise.all([
        sessionManager.createSession('concurrent-1'),
        sessionManager.createSession('concurrent-2'),
        sessionManager.createSession('concurrent-3')
      ]);

      // Perform concurrent operations
      const operations = sessions.map(async (session) => {
        await sessionManager.sendCommand(session.id, 'echo concurrent test');
        await sessionManager.createWindow(session.id, 'concurrent-window');
        return sessionManager.resizeSession(session.id, 100, 30);
      });

      const results = await Promise.all(operations);
      expect(results.every(result => result === true)).toBe(true);

      // All sessions should still exist
      sessions.forEach(session => {
        const existingSession = sessionManager.getSession(session.id);
        expect(existingSession).not.toBeNull();
        expect(existingSession?.windowCount).toBe(2);
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle errors in event listeners gracefully', () => {
      const faultyListener = () => {
        throw new Error('Listener error');
      };
      const workingListener = jest.fn();

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      sessionManager.on('error-test', faultyListener);
      sessionManager.on('error-test', workingListener);

      // Emit event - should not crash the system
      (sessionManager as any).emit('error-test', { data: 'test' });

      expect(workingListener).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    it('should cleanup resources properly', () => {
      const session1 = sessionManager.createSession('cleanup-test-1');
      const session2 = sessionManager.createSession('cleanup-test-2');

      sessionManager.on('test-event', () => {});
      sessionManager.on('another-event', () => {});

      expect(sessionManager.listSessions()).not.toHaveLength(0);

      sessionManager.cleanup();

      expect(sessionManager.listSessions()).toHaveLength(0);
    });

    it('should handle malformed session data', async () => {
      // Create session with minimal data
      const session = await sessionManager.createSession('');

      expect(session.name).toBeTruthy(); // Should have auto-generated name
      expect(session.status).toBe('active');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large numbers of sessions efficiently', async () => {
      const sessionCount = 50;
      const startTime = Date.now();

      const sessions = await Promise.all(
        Array.from({ length: sessionCount }, (_, i) =>
          sessionManager.createSession(`perf-test-session-${i}`)
        )
      );

      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(sessions).toHaveLength(sessionCount);
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
      expect(sessionManager.listSessions()).toHaveLength(sessionCount);
    });

    it('should handle rapid command execution', async () => {
      const session = await sessionManager.createSession('rapid-commands-test');
      const commandCount = 100;

      const commands = Array.from({ length: commandCount }, (_, i) =>
        sessionManager.sendCommand(session.id, `echo "Command ${i}"`)
      );

      const results = await Promise.all(commands);
      expect(results.every(result => result === true)).toBe(true);
    });
  });
});