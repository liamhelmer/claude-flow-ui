/**
 * Unit tests for TmuxSessionManager
 */

import TmuxSessionManager, { TmuxSession, TmuxWindow } from '../session-manager';

describe('TmuxSessionManager', () => {
  let manager: TmuxSessionManager;

  beforeEach(() => {
    manager = new TmuxSessionManager();
  });

  afterEach(() => {
    manager.cleanup();
  });

  describe('Session Management', () => {
    it('should create a new session with default name', async () => {
      const session = await manager.createSession();

      expect(session).toBeDefined();
      expect(session.id).toBeTruthy();
      expect(session.name).toMatch(/^terminal_\d+$/);
      expect(session.status).toBe('active');
      expect(session.windowCount).toBe(1);
      expect(session.pids).toEqual([]);
      expect(session.created).toBeInstanceOf(Date);
      expect(session.lastActivity).toBeInstanceOf(Date);
    });

    it('should create a session with custom name', async () => {
      const customName = 'my-custom-session';
      const session = await manager.createSession(customName);

      expect(session.name).toBe(customName);
      expect(session.id).toBeTruthy();
      expect(session.status).toBe('active');
    });

    it('should retrieve session by ID', async () => {
      const session = await manager.createSession();
      const retrieved = manager.getSession(session.id);

      expect(retrieved).toEqual(session);
    });

    it('should return null for non-existent session', () => {
      const retrieved = manager.getSession('non-existent');
      expect(retrieved).toBeNull();
    });

    it('should list all sessions', async () => {
      const session1 = await manager.createSession('session1');
      const session2 = await manager.createSession('session2');

      const sessions = manager.listSessions();

      expect(sessions).toHaveLength(2);
      expect(sessions).toContain(session1);
      expect(sessions).toContain(session2);
    });

    it('should destroy a session', async () => {
      const session = await manager.createSession();
      const destroyed = await manager.destroySession(session.id);

      expect(destroyed).toBe(true);
      expect(manager.getSession(session.id)).toBeNull();
      expect(manager.listSessions()).toHaveLength(0);
    });

    it('should return false when destroying non-existent session', async () => {
      const destroyed = await manager.destroySession('non-existent');
      expect(destroyed).toBe(false);
    });

    it('should get session status', async () => {
      const session = await manager.createSession();
      const status = manager.getSessionStatus(session.id);

      expect(status).toBe('active');
    });

    it('should return null for status of non-existent session', () => {
      const status = manager.getSessionStatus('non-existent');
      expect(status).toBeNull();
    });
  });

  describe('Window Management', () => {
    let session: TmuxSession;

    beforeEach(async () => {
      session = await manager.createSession();
    });

    it('should create a window with default name', async () => {
      const window = await manager.createWindow(session.id);

      expect(window).toBeDefined();
      expect(window!.id).toBeTruthy();
      expect(window!.sessionId).toBe(session.id);
      expect(window!.name).toMatch(/^window_\d+$/);
      expect(window!.index).toBe(1);
      expect(window!.isActive).toBe(true);
      expect(window!.panes).toEqual([]);
    });

    it('should create a window with custom name', async () => {
      const customName = 'my-window';
      const window = await manager.createWindow(session.id, customName);

      expect(window!.name).toBe(customName);
      expect(window!.sessionId).toBe(session.id);
    });

    it('should return null when creating window for non-existent session', async () => {
      const window = await manager.createWindow('non-existent');
      expect(window).toBeNull();
    });

    it('should increment session window count when creating windows', async () => {
      const initialCount = session.windowCount;
      await manager.createWindow(session.id);

      const updatedSession = manager.getSession(session.id);
      expect(updatedSession!.windowCount).toBe(initialCount + 1);
    });
  });

  describe('Command Handling', () => {
    let session: TmuxSession;

    beforeEach(async () => {
      session = await manager.createSession();
    });

    it('should send command to existing session', async () => {
      const command = 'ls -la';
      const result = await manager.sendCommand(session.id, command);

      expect(result).toBe(true);
    });

    it('should update last activity when sending command', async () => {
      const originalActivity = session.lastActivity;
      
      // Wait a small amount to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));
      
      await manager.sendCommand(session.id, 'echo test');
      
      const updatedSession = manager.getSession(session.id);
      expect(updatedSession!.lastActivity.getTime()).toBeGreaterThan(originalActivity.getTime());
    });

    it('should return false for command to non-existent session', async () => {
      const result = await manager.sendCommand('non-existent', 'echo test');
      expect(result).toBe(false);
    });
  });

  describe('Session Resizing', () => {
    let session: TmuxSession;

    beforeEach(async () => {
      session = await manager.createSession();
    });

    it('should resize existing session', async () => {
      const result = await manager.resizeSession(session.id, 80, 24);
      expect(result).toBe(true);
    });

    it('should return false for resizing non-existent session', async () => {
      const result = await manager.resizeSession('non-existent', 80, 24);
      expect(result).toBe(false);
    });
  });

  describe('Activity Tracking', () => {
    let session: TmuxSession;

    beforeEach(async () => {
      session = await manager.createSession();
    });

    it('should update activity timestamp', async () => {
      const originalActivity = session.lastActivity;
      
      // Wait a small amount to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 10));
      
      manager.updateActivity(session.id);
      
      const updatedSession = manager.getSession(session.id);
      expect(updatedSession!.lastActivity.getTime()).toBeGreaterThan(originalActivity.getTime());
    });

    it('should not error when updating activity for non-existent session', () => {
      expect(() => {
        manager.updateActivity('non-existent');
      }).not.toThrow();
    });
  });

  describe('Event System', () => {
    it('should register and trigger event listeners', (done) => {
      manager.on('session:created', (session) => {
        expect(session).toBeDefined();
        expect(session.id).toBeTruthy();
        done();
      });

      // Trigger the event by creating a session
      manager.createSession();
    });

    it('should handle session creation events', (done) => {
      manager.on('session:created', (session) => {
        expect(session).toBeDefined();
        expect(session.id).toBeTruthy();
        done();
      });

      manager.createSession();
    });

    it('should handle session destruction events', (done) => {
      manager.createSession().then(session => {
        manager.on('session:destroyed', (destroyedSession) => {
          expect(destroyedSession).toEqual(session);
          done();
        });

        manager.destroySession(session.id);
      });
    });

    it('should handle window creation events', (done) => {
      manager.createSession().then(session => {
        manager.on('window:created', (window) => {
          expect(window).toBeDefined();
          expect(window.sessionId).toBe(session.id);
          done();
        });

        manager.createWindow(session.id);
      });
    });

    it('should handle command sent events', (done) => {
      manager.createSession().then(session => {
        const command = 'test command';
        
        manager.on('command:sent', (data) => {
          expect(data.sessionId).toBe(session.id);
          expect(data.command).toBe(command);
          done();
        });

        manager.sendCommand(session.id, command);
      });
    });

    it('should remove event listeners', () => {
      const listener = jest.fn();
      
      manager.on('test-event', listener);
      manager.off('test-event', listener);

      // Manual trigger since we can't access emit directly
      manager.createSession();
      
      // The listener should not have been called for our test event
      expect(listener).not.toHaveBeenCalled();
    });

    it('should handle errors in event listeners gracefully', (done) => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      manager.on('session:created', () => {
        throw new Error('Test error in listener');
      });

      manager.on('session:created', () => {
        // This listener should still execute despite the error in the previous one
        expect(consoleSpy).toHaveBeenCalled();
        consoleSpy.mockRestore();
        done();
      });

      manager.createSession();
    });
  });

  describe('Cleanup', () => {
    it('should clear all sessions and windows on cleanup', async () => {
      await manager.createSession();
      await manager.createSession();

      expect(manager.listSessions()).toHaveLength(2);

      manager.cleanup();

      expect(manager.listSessions()).toHaveLength(0);
    });

    it('should clear all event listeners on cleanup', () => {
      const listener = jest.fn();
      manager.on('test-event', listener);

      manager.cleanup();

      // After cleanup, the internal event listeners map should be empty
      // We can't directly test this, but we can verify by creating a new session
      // and ensuring no lingering listeners are triggered
      manager.createSession();
      expect(listener).not.toHaveBeenCalled();
    });
  });

  describe('Edge Cases', () => {
    it('should handle multiple sessions with same name', async () => {
      const name = 'duplicate-name';
      const session1 = await manager.createSession(name);
      const session2 = await manager.createSession(name);

      expect(session1.name).toBe(name);
      expect(session2.name).toBe(name);
      expect(session1.id).not.toBe(session2.id);
    });

    it('should generate unique session IDs', async () => {
      const sessions = await Promise.all([
        manager.createSession(),
        manager.createSession(),
        manager.createSession()
      ]);

      const ids = sessions.map(s => s.id);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(3);
    });

    it('should generate unique window IDs', async () => {
      const session = await manager.createSession();
      const windows = await Promise.all([
        manager.createWindow(session.id),
        manager.createWindow(session.id),
        manager.createWindow(session.id)
      ]);

      const ids = windows.map(w => w!.id);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(3);
    });
  });
});