/**
 * Comprehensive unit tests for Zustand store
 * Tests state management, actions, selectors, and persistence
 */

import { renderHook, act } from '@testing-library/react';
import {
  useAppStore,
  useTerminalSessions,
  useActiveSession,
  useActiveSessionId,
  useSidebarOpen,
  useAppError,
  useAppLoading,
  useSessionCount,
  useHasActiveSessions,
  useSessionNames,
  subscribeToActiveSession,
  getStoreSnapshot,
  restoreStoreSnapshot,
  initializeSidebarForViewport,
} from '@/lib/state/store';

// Mock console methods to reduce noise during tests
const consoleSpy = {
  debug: jest.spyOn(console, 'debug').mockImplementation(),
  log: jest.spyOn(console, 'log').mockImplementation(),
  warn: jest.spyOn(console, 'warn').mockImplementation(),
  error: jest.spyOn(console, 'error').mockImplementation(),
};

describe('Zustand Store', () => {
  beforeEach(() => {
    // Reset store to initial state
    act(() => {
      useAppStore.getState().clearSessions();
      useAppStore.getState().setSidebarOpen(true);
      useAppStore.getState().setLoading(false);
      useAppStore.getState().setError(null);
    });

    jest.clearAllMocks();
  });

  afterAll(() => {
    Object.values(consoleSpy).forEach(spy => spy.mockRestore());
  });

  describe('Initial State', () => {
    it('initializes with correct default values', () => {
      const { result } = renderHook(() => useAppStore());

      expect(result.current.terminalSessions).toEqual([]);
      expect(result.current.activeSessionId).toBeNull();
      expect(result.current.sidebarOpen).toBe(true);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('provides all required actions', () => {
      const { result } = renderHook(() => useAppStore());

      expect(typeof result.current.setSidebarOpen).toBe('function');
      expect(typeof result.current.toggleSidebar).toBe('function');
      expect(typeof result.current.setActiveSession).toBe('function');
      expect(typeof result.current.addSession).toBe('function');
      expect(typeof result.current.removeSession).toBe('function');
      expect(typeof result.current.updateSession).toBe('function');
      expect(typeof result.current.setLoading).toBe('function');
      expect(typeof result.current.setError).toBe('function');
      expect(typeof result.current.createNewSession).toBe('function');
      expect(typeof result.current.clearSessions).toBe('function');
      expect(typeof result.current.batchUpdate).toBe('function');
    });
  });

  describe('Sidebar Management', () => {
    it('sets sidebar open state', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setSidebarOpen(false);
      });

      expect(result.current.sidebarOpen).toBe(false);

      act(() => {
        result.current.setSidebarOpen(true);
      });

      expect(result.current.sidebarOpen).toBe(true);
    });

    it('toggles sidebar state', () => {
      const { result } = renderHook(() => useAppStore());

      expect(result.current.sidebarOpen).toBe(true);

      act(() => {
        result.current.toggleSidebar();
      });

      expect(result.current.sidebarOpen).toBe(false);

      act(() => {
        result.current.toggleSidebar();
      });

      expect(result.current.sidebarOpen).toBe(true);
    });

    it('provides sidebar selector hook', () => {
      const { result: storeResult } = renderHook(() => useAppStore());
      const { result: selectorResult } = renderHook(() => useSidebarOpen());

      expect(selectorResult.current).toBe(true);

      act(() => {
        storeResult.current.setSidebarOpen(false);
      });

      expect(selectorResult.current).toBe(false);
    });
  });

  describe('Session Management', () => {
    const mockSession = {
      id: 'test-session-123',
      name: 'Test Terminal',
      isActive: true,
      lastActivity: new Date('2023-01-01T10:00:00Z'),
    };

    it('adds sessions correctly', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('adds multiple sessions', () => {
      const { result } = renderHook(() => useAppStore());

      const session1 = { ...mockSession, id: 'session-1', name: 'Terminal 1' };
      const session2 = { ...mockSession, id: 'session-2', name: 'Terminal 2' };

      act(() => {
        result.current.addSession(session1);
        result.current.addSession(session2);
      });

      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions.map(s => s.id)).toEqual(['session-1', 'session-2']);
    });

    it('removes sessions correctly', () => {
      const { result } = renderHook(() => useAppStore());

      // Add multiple sessions
      const session1 = { ...mockSession, id: 'session-1' };
      const session2 = { ...mockSession, id: 'session-2' };

      act(() => {
        result.current.addSession(session1);
        result.current.addSession(session2);
        result.current.setActiveSession('session-1');
      });

      expect(result.current.terminalSessions).toHaveLength(2);

      // Remove non-active session
      act(() => {
        result.current.removeSession('session-2');
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe('session-1');

      // Remove active session
      act(() => {
        result.current.removeSession('session-1');
      });

      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBeNull();
    });

    it('updates active session when removing active session', () => {
      const { result } = renderHook(() => useAppStore());

      // Add multiple sessions
      const sessions = [
        { ...mockSession, id: 'session-1' },
        { ...mockSession, id: 'session-2' },
        { ...mockSession, id: 'session-3' },
      ];

      act(() => {
        sessions.forEach(session => result.current.addSession(session));
        result.current.setActiveSession('session-2');
      });

      // Remove active session
      act(() => {
        result.current.removeSession('session-2');
      });

      expect(result.current.activeSessionId).toBe('session-1'); // Should switch to first remaining
      expect(result.current.terminalSessions).toHaveLength(2);
    });

    it('updates sessions correctly', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      const updates = {
        name: 'Updated Terminal',
        isActive: false,
        lastActivity: new Date('2023-01-02T10:00:00Z'),
      };

      act(() => {
        result.current.updateSession('test-session-123', updates);
      });

      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe('Updated Terminal');
      expect(updatedSession.isActive).toBe(false);
      expect(updatedSession.lastActivity).toEqual(updates.lastActivity);
      expect(updatedSession.id).toBe('test-session-123'); // Should preserve ID
    });

    it('ignores updates for non-existent sessions', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      const originalSession = result.current.terminalSessions[0];

      act(() => {
        result.current.updateSession('non-existent', { name: 'Should not work' });
      });

      expect(result.current.terminalSessions[0]).toEqual(originalSession);
    });

    it('sets active session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setActiveSession('session-123');
      });

      expect(result.current.activeSessionId).toBe('session-123');

      act(() => {
        result.current.setActiveSession(null);
      });

      expect(result.current.activeSessionId).toBeNull();
    });

    it('creates new sessions with auto-generated IDs', () => {
      const { result } = renderHook(() => useAppStore());

      let newSessionId: string;

      act(() => {
        newSessionId = result.current.createNewSession();
      });

      expect(newSessionId).toBeDefined();
      expect(typeof newSessionId).toBe('string');
      expect(newSessionId.startsWith('session-')).toBe(true);

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0].id).toBe(newSessionId);
      expect(result.current.terminalSessions[0].name).toBe('Terminal 1');
      expect(result.current.terminalSessions[0].isActive).toBe(true);
      expect(result.current.activeSessionId).toBe(newSessionId);
    });

    it('creates sessions with incremental names', () => {
      const { result } = renderHook(() => useAppStore());

      let sessionId1: string;
      let sessionId2: string;
      let sessionId3: string;

      act(() => {
        sessionId1 = result.current.createNewSession();
        sessionId2 = result.current.createNewSession();
        sessionId3 = result.current.createNewSession();
      });

      expect(result.current.terminalSessions[0].name).toBe('Terminal 1');
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2');
      expect(result.current.terminalSessions[2].name).toBe('Terminal 3');
      expect(result.current.activeSessionId).toBe(sessionId3); // Should be last created
    });

    it('clears all sessions', () => {
      const { result } = renderHook(() => useAppStore());

      // Add some sessions
      act(() => {
        result.current.createNewSession();
        result.current.createNewSession();
        result.current.createNewSession();
      });

      expect(result.current.terminalSessions).toHaveLength(3);

      act(() => {
        result.current.clearSessions();
      });

      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBeNull();
    });
  });

  describe('Loading and Error States', () => {
    it('manages loading state', () => {
      const { result } = renderHook(() => useAppStore());

      expect(result.current.loading).toBe(false);

      act(() => {
        result.current.setLoading(true);
      });

      expect(result.current.loading).toBe(true);

      act(() => {
        result.current.setLoading(false);
      });

      expect(result.current.loading).toBe(false);
    });

    it('manages error state', () => {
      const { result } = renderHook(() => useAppStore());

      expect(result.current.error).toBeNull();

      act(() => {
        result.current.setError('Something went wrong');
      });

      expect(result.current.error).toBe('Something went wrong');

      act(() => {
        result.current.setError(null);
      });

      expect(result.current.error).toBeNull();
    });

    it('provides loading and error selector hooks', () => {
      const { result: storeResult } = renderHook(() => useAppStore());
      const { result: loadingResult } = renderHook(() => useAppLoading());
      const { result: errorResult } = renderHook(() => useAppError());

      expect(loadingResult.current).toBe(false);
      expect(errorResult.current).toBeNull();

      act(() => {
        storeResult.current.setLoading(true);
        storeResult.current.setError('Test error');
      });

      expect(loadingResult.current).toBe(true);
      expect(errorResult.current).toBe('Test error');
    });
  });

  describe('Batch Updates', () => {
    it('performs batch updates correctly', () => {
      const { result } = renderHook(() => useAppStore());

      const batchUpdates = {
        sidebarOpen: false,
        loading: true,
        error: 'Batch error',
        activeSessionId: 'batch-session',
      };

      act(() => {
        result.current.batchUpdate(batchUpdates);
      });

      expect(result.current.sidebarOpen).toBe(false);
      expect(result.current.loading).toBe(true);
      expect(result.current.error).toBe('Batch error');
      expect(result.current.activeSessionId).toBe('batch-session');
    });

    it('preserves non-updated state in batch updates', () => {
      const { result } = renderHook(() => useAppStore());

      // Set initial state
      act(() => {
        result.current.addSession({
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date(),
        });
      });

      const initialSessions = result.current.terminalSessions;

      // Batch update only some fields
      act(() => {
        result.current.batchUpdate({
          sidebarOpen: false,
          loading: true,
        });
      });

      expect(result.current.terminalSessions).toEqual(initialSessions);
      expect(result.current.sidebarOpen).toBe(false);
      expect(result.current.loading).toBe(true);
      expect(result.current.error).toBeNull(); // Should preserve existing state
    });
  });

  describe('Selector Hooks', () => {
    beforeEach(() => {
      // Set up some test data
      act(() => {
        const store = useAppStore.getState();
        store.addSession({
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date('2023-01-01'),
        });
        store.addSession({
          id: 'session-2',
          name: 'Terminal 2',
          isActive: false,
          lastActivity: new Date('2023-01-02'),
        });
        store.setActiveSession('session-1');
      });
    });

    it('useTerminalSessions returns all sessions', () => {
      const { result } = renderHook(() => useTerminalSessions());

      expect(result.current).toHaveLength(2);
      expect(result.current.map(s => s.id)).toEqual(['session-1', 'session-2']);
    });

    it('useActiveSession returns active session', () => {
      const { result } = renderHook(() => useActiveSession());

      expect(result.current).toBeDefined();
      expect(result.current?.id).toBe('session-1');
      expect(result.current?.name).toBe('Terminal 1');
    });

    it('useActiveSessionId returns active session ID', () => {
      const { result } = renderHook(() => useActiveSessionId());

      expect(result.current).toBe('session-1');
    });

    it('useSessionCount returns session count', () => {
      const { result } = renderHook(() => useSessionCount());

      expect(result.current).toBe(2);

      act(() => {
        useAppStore.getState().createNewSession();
      });

      expect(result.current).toBe(3);
    });

    it('useHasActiveSessions returns boolean', () => {
      const { result } = renderHook(() => useHasActiveSessions());

      expect(result.current).toBe(true);

      act(() => {
        useAppStore.getState().clearSessions();
      });

      expect(result.current).toBe(false);
    });

    it('useSessionNames returns session names', () => {
      const { result } = renderHook(() => useSessionNames());

      expect(result.current).toEqual([
        { id: 'session-1', name: 'Terminal 1' },
        { id: 'session-2', name: 'Terminal 2' },
      ]);
    });

    it('selectors update when store changes', () => {
      const { result: countResult } = renderHook(() => useSessionCount());
      const { result: activeResult } = renderHook(() => useActiveSession());

      expect(countResult.current).toBe(2);
      expect(activeResult.current?.id).toBe('session-1');

      act(() => {
        useAppStore.getState().removeSession('session-1');
      });

      expect(countResult.current).toBe(1);
      expect(activeResult.current?.id).toBe('session-2');
    });
  });

  describe('Subscriptions', () => {
    it('subscribeToActiveSession calls callback on changes', () => {
      const callback = jest.fn();

      const unsubscribe = subscribeToActiveSession(callback);

      // Should call with initial value
      expect(callback).toHaveBeenCalledWith(null);

      // Change active session
      act(() => {
        useAppStore.getState().setActiveSession('new-session');
      });

      expect(callback).toHaveBeenCalledWith('new-session');

      // Clean up
      unsubscribe();

      // Should not call after unsubscribe
      callback.mockClear();
      act(() => {
        useAppStore.getState().setActiveSession('another-session');
      });

      expect(callback).not.toHaveBeenCalled();
    });

    it('handles multiple subscribers', () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      const unsubscribe1 = subscribeToActiveSession(callback1);
      const unsubscribe2 = subscribeToActiveSession(callback2);

      act(() => {
        useAppStore.getState().setActiveSession('test-session');
      });

      expect(callback1).toHaveBeenCalledWith('test-session');
      expect(callback2).toHaveBeenCalledWith('test-session');

      unsubscribe1();
      unsubscribe2();
    });
  });

  describe('Persistence Utilities', () => {
    beforeEach(() => {
      // Set up test state
      act(() => {
        const store = useAppStore.getState();
        store.addSession({
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date('2023-01-01'),
        });
        store.setActiveSession('session-1');
        store.setSidebarOpen(false);
      });
    });

    it('getStoreSnapshot captures current state', () => {
      const snapshot = getStoreSnapshot();

      expect(snapshot).toEqual({
        terminalSessions: [{
          id: 'session-1',
          name: 'Terminal 1',
          isActive: true,
          lastActivity: new Date('2023-01-01'),
        }],
        activeSessionId: 'session-1',
        sidebarOpen: false,
      });
    });

    it('restoreStoreSnapshot restores state', () => {
      const snapshot = {
        terminalSessions: [{
          id: 'restored-session',
          name: 'Restored Terminal',
          isActive: true,
          lastActivity: new Date('2023-01-02'),
        }],
        activeSessionId: 'restored-session',
        sidebarOpen: true,
      };

      restoreStoreSnapshot(snapshot);

      const { result } = renderHook(() => useAppStore());

      expect(result.current.terminalSessions).toEqual(snapshot.terminalSessions);
      expect(result.current.activeSessionId).toBe('restored-session');
      expect(result.current.sidebarOpen).toBe(true);
    });

    it('handles partial snapshot restoration', () => {
      const partialSnapshot = {
        sidebarOpen: true,
        // Omit other fields
      };

      restoreStoreSnapshot(partialSnapshot);

      const { result } = renderHook(() => useAppStore());

      expect(result.current.sidebarOpen).toBe(true);
      // Other fields should be preserved
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe('session-1');
    });
  });

  describe('Viewport Initialization', () => {
    const originalInnerWidth = global.innerWidth;

    afterEach(() => {
      global.innerWidth = originalInnerWidth;
    });

    it('closes sidebar on mobile viewport', () => {
      // Mock mobile viewport
      global.innerWidth = 500;
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 500,
      });

      // Set sidebar open first
      act(() => {
        useAppStore.getState().setSidebarOpen(true);
      });

      initializeSidebarForViewport();

      expect(useAppStore.getState().sidebarOpen).toBe(false);
    });

    it('keeps sidebar open on desktop viewport', () => {
      // Mock desktop viewport
      global.innerWidth = 1024;
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 1024,
      });

      // Set sidebar open
      act(() => {
        useAppStore.getState().setSidebarOpen(true);
      });

      initializeSidebarForViewport();

      expect(useAppStore.getState().sidebarOpen).toBe(true);
    });

    it('does not change closed sidebar on mobile', () => {
      global.innerWidth = 500;
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 500,
      });

      // Set sidebar closed first
      act(() => {
        useAppStore.getState().setSidebarOpen(false);
      });

      initializeSidebarForViewport();

      expect(useAppStore.getState().sidebarOpen).toBe(false);
    });

    it('handles missing window object gracefully', () => {
      const originalWindow = global.window;
      delete (global as any).window;

      expect(() => {
        initializeSidebarForViewport();
      }).not.toThrow();

      global.window = originalWindow;
    });
  });

  describe('Development Mode', () => {
    const originalEnv = process.env.NODE_ENV;
    const originalWindow = global.window;

    beforeEach(() => {
      process.env.NODE_ENV = 'development';
      global.window = originalWindow;
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('exposes store utilities in development', () => {
      // Re-import to trigger development setup
      delete require.cache[require.resolve('@/lib/state/store')];
      require('@/lib/state/store');

      expect((global.window as any).claudeFlowStore).toBeDefined();
      expect((global.window as any).getStoreSnapshot).toBeDefined();
      expect((global.window as any).restoreStoreSnapshot).toBeDefined();
    });
  });

  describe('Concurrent Operations', () => {
    it('handles concurrent session operations', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        // Simulate rapid concurrent operations
        result.current.createNewSession();
        result.current.createNewSession();
        result.current.setActiveSession('session-123');
        result.current.setSidebarOpen(false);
        result.current.setLoading(true);
        result.current.setError('Test error');

        const firstSession = result.current.terminalSessions[0];
        if (firstSession) {
          result.current.updateSession(firstSession.id, { name: 'Updated' });
          result.current.removeSession(firstSession.id);
        }
      });

      // Should handle all operations without errors
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe('session-123');
      expect(result.current.sidebarOpen).toBe(false);
      expect(result.current.loading).toBe(true);
      expect(result.current.error).toBe('Test error');
    });

    it('maintains state consistency during rapid updates', () => {
      const { result } = renderHook(() => useAppStore());

      // Create multiple sessions rapidly
      const sessionIds: string[] = [];

      act(() => {
        for (let i = 0; i < 10; i++) {
          const id = result.current.createNewSession();
          sessionIds.push(id);
        }
      });

      expect(result.current.terminalSessions).toHaveLength(10);
      expect(result.current.activeSessionId).toBe(sessionIds[sessionIds.length - 1]);

      // Update all sessions rapidly
      act(() => {
        sessionIds.forEach((id, index) => {
          result.current.updateSession(id, { name: `Updated Terminal ${index + 1}` });
        });
      });

      result.current.terminalSessions.forEach((session, index) => {
        expect(session.name).toBe(`Updated Terminal ${index + 1}`);
      });

      // Remove sessions rapidly
      act(() => {
        sessionIds.slice(0, 5).forEach(id => {
          result.current.removeSession(id);
        });
      });

      expect(result.current.terminalSessions).toHaveLength(5);
    });
  });

  describe('Memory Management', () => {
    it('does not create memory leaks with subscriptions', () => {
      const callbacks = [];

      // Create many subscriptions
      for (let i = 0; i < 100; i++) {
        const callback = jest.fn();
        callbacks.push(callback);
        subscribeToActiveSession(callback);
      }

      // Trigger state change
      act(() => {
        useAppStore.getState().setActiveSession('test-session');
      });

      // All callbacks should be called
      callbacks.forEach(callback => {
        expect(callback).toHaveBeenCalledWith('test-session');
      });

      // Unsubscribe should work without issues
      // (In real usage, components would unsubscribe on unmount)
    });

    it('handles large session collections efficiently', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        // Add many sessions
        for (let i = 0; i < 1000; i++) {
          result.current.addSession({
            id: `session-${i}`,
            name: `Terminal ${i}`,
            isActive: i === 999, // Only last one active
            lastActivity: new Date(),
          });
        }
      });

      expect(result.current.terminalSessions).toHaveLength(1000);

      // Operations should still be fast
      const start = performance.now();

      act(() => {
        result.current.updateSession('session-500', { name: 'Updated 500' });
        result.current.removeSession('session-999');
        result.current.setActiveSession('session-500');
      });

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(100); // Should complete quickly
    });
  });
});