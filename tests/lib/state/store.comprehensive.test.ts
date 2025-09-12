import { renderHook, act } from '@testing-library/react';
import { useAppStore } from '@/lib/state/store';
import type { TerminalSession } from '@/types';

// Mock Zustand devtools
jest.mock('zustand/middleware', () => ({
  devtools: (fn: any) => fn,
}));

describe('useAppStore - Comprehensive Tests', () => {
  beforeEach(() => {
    // Reset store state before each test
    act(() => {
      useAppStore.getState().clearSessions();
      useAppStore.setState({
        sidebarOpen: true,
        loading: false,
        error: null,
        activeSessionId: null,
      });
    });
  });

  describe('Initial State', () => {
    it('has correct default state', () => {
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

      // Initial state is true
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

    it('handles rapid sidebar toggles', () => {
      const { result } = renderHook(() => useAppStore());

      const initialState = result.current.sidebarOpen;

      // Toggle multiple times rapidly
      act(() => {
        result.current.toggleSidebar();
        result.current.toggleSidebar();
        result.current.toggleSidebar();
        result.current.toggleSidebar();
      });

      // Should end up in same state as initial
      expect(result.current.sidebarOpen).toBe(initialState);
    });
  });

  describe('Session Management', () => {
    const mockSession: TerminalSession = {
      id: 'test-session-1',
      name: 'Test Terminal',
      isActive: true,
      lastActivity: new Date(),
    };

    it('adds a session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('adds multiple sessions', () => {
      const { result } = renderHook(() => useAppStore());

      const session2 = { ...mockSession, id: 'test-session-2', name: 'Test Terminal 2' };

      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
      });

      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
      expect(result.current.terminalSessions[1]).toEqual(session2);
    });

    it('removes a session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      expect(result.current.terminalSessions).toHaveLength(1);

      act(() => {
        result.current.removeSession(mockSession.id);
      });

      expect(result.current.terminalSessions).toHaveLength(0);
    });

    it('handles removing non-existent session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      expect(result.current.terminalSessions).toHaveLength(1);

      act(() => {
        result.current.removeSession('non-existent-id');
      });

      // Should still have the original session
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('updates session properties', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      const updates = {
        name: 'Updated Terminal Name',
        isActive: false,
      };

      act(() => {
        result.current.updateSession(mockSession.id, updates);
      });

      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe('Updated Terminal Name');
      expect(updatedSession.isActive).toBe(false);
      expect(updatedSession.id).toBe(mockSession.id); // Should preserve unchanged properties
    });

    it('handles updating non-existent session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      act(() => {
        result.current.updateSession('non-existent-id', { name: 'New Name' });
      });

      // Original session should remain unchanged
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('clears all sessions', () => {
      const { result } = renderHook(() => useAppStore());

      const session2 = { ...mockSession, id: 'test-session-2' };

      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
      });

      expect(result.current.terminalSessions).toHaveLength(2);

      act(() => {
        result.current.clearSessions();
      });

      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBeNull();
    });
  });

  describe('Active Session Management', () => {
    const mockSession1: TerminalSession = {
      id: 'session-1',
      name: 'Terminal 1',
      isActive: true,
      lastActivity: new Date(),
    };

    const mockSession2: TerminalSession = {
      id: 'session-2',
      name: 'Terminal 2',
      isActive: true,
      lastActivity: new Date(),
    };

    it('sets active session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setActiveSession('session-1');
      });

      expect(result.current.activeSessionId).toBe('session-1');
    });

    it('sets active session to null', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setActiveSession('session-1');
      });

      expect(result.current.activeSessionId).toBe('session-1');

      act(() => {
        result.current.setActiveSession(null);
      });

      expect(result.current.activeSessionId).toBeNull();
    });

    it('handles removing active session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession1);
        result.current.addSession(mockSession2);
        result.current.setActiveSession('session-1');
      });

      expect(result.current.activeSessionId).toBe('session-1');

      act(() => {
        result.current.removeSession('session-1');
      });

      // Should set active session to the first remaining session
      expect(result.current.activeSessionId).toBe('session-2');
      expect(result.current.terminalSessions).toHaveLength(1);
    });

    it('sets active session to null when removing last session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession1);
        result.current.setActiveSession('session-1');
      });

      expect(result.current.activeSessionId).toBe('session-1');

      act(() => {
        result.current.removeSession('session-1');
      });

      expect(result.current.activeSessionId).toBeNull();
      expect(result.current.terminalSessions).toHaveLength(0);
    });

    it('preserves active session when removing different session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession1);
        result.current.addSession(mockSession2);
        result.current.setActiveSession('session-1');
      });

      expect(result.current.activeSessionId).toBe('session-1');

      act(() => {
        result.current.removeSession('session-2');
      });

      // Active session should remain unchanged
      expect(result.current.activeSessionId).toBe('session-1');
      expect(result.current.terminalSessions).toHaveLength(1);
    });
  });

  describe('Session Creation', () => {
    it('creates new session with generated ID', () => {
      const { result } = renderHook(() => useAppStore());

      let sessionId: string;

      act(() => {
        sessionId = result.current.createNewSession();
      });

      expect(sessionId!).toBeDefined();
      expect(typeof sessionId!).toBe('string');
      expect(result.current.terminalSessions).toHaveLength(1);

      const newSession = result.current.terminalSessions[0];
      expect(newSession.id).toBe(sessionId!);
      expect(newSession.name).toBe('Terminal 1');
      expect(newSession.isActive).toBe(true);
      expect(newSession.lastActivity).toBeInstanceOf(Date);
    });

    it('generates unique session IDs', () => {
      const { result } = renderHook(() => useAppStore());

      let sessionId1: string;
      let sessionId2: string;

      act(() => {
        sessionId1 = result.current.createNewSession();
      });

      act(() => {
        sessionId2 = result.current.createNewSession();
      });

      expect(sessionId1!).not.toBe(sessionId2!);
      expect(result.current.terminalSessions).toHaveLength(2);
    });

    it('sets new session as active', () => {
      const { result } = renderHook(() => useAppStore());

      let sessionId: string;

      act(() => {
        sessionId = result.current.createNewSession();
      });

      expect(result.current.activeSessionId).toBe(sessionId!);
    });

    it('increments session names correctly', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.createNewSession();
        result.current.createNewSession();
        result.current.createNewSession();
      });

      expect(result.current.terminalSessions).toHaveLength(3);
      expect(result.current.terminalSessions[0].name).toBe('Terminal 1');
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2');
      expect(result.current.terminalSessions[2].name).toBe('Terminal 3');
    });

    it('continues numbering after session removal', () => {
      const { result } = renderHook(() => useAppStore());

      let sessionId1: string;

      act(() => {
        sessionId1 = result.current.createNewSession();
        result.current.createNewSession();
      });

      act(() => {
        result.current.removeSession(sessionId1!);
      });

      act(() => {
        result.current.createNewSession();
      });

      // Should continue from the highest count, not reset
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[1].name).toBe('Terminal 3');
    });
  });

  describe('Loading and Error State', () => {
    it('sets loading state', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setLoading(true);
      });

      expect(result.current.loading).toBe(true);

      act(() => {
        result.current.setLoading(false);
      });

      expect(result.current.loading).toBe(false);
    });

    it('sets error state', () => {
      const { result } = renderHook(() => useAppStore());

      const errorMessage = 'Something went wrong';

      act(() => {
        result.current.setError(errorMessage);
      });

      expect(result.current.error).toBe(errorMessage);

      act(() => {
        result.current.setError(null);
      });

      expect(result.current.error).toBeNull();
    });

    it('handles multiple error state changes', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setError('First error');
      });

      expect(result.current.error).toBe('First error');

      act(() => {
        result.current.setError('Second error');
      });

      expect(result.current.error).toBe('Second error');

      act(() => {
        result.current.setError(null);
      });

      expect(result.current.error).toBeNull();
    });

    it('handles loading state during async operations', async () => {
      const { result } = renderHook(() => useAppStore());

      // Simulate async operation
      act(() => {
        result.current.setLoading(true);
      });

      expect(result.current.loading).toBe(true);

      // Simulate operation completion
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        result.current.setLoading(false);
      });

      expect(result.current.loading).toBe(false);
    });
  });

  describe('State Persistence and Reactivity', () => {
    it('persists state changes across multiple hook calls', () => {
      const { result: result1 } = renderHook(() => useAppStore());
      const { result: result2 } = renderHook(() => useAppStore());

      act(() => {
        result1.current.setSidebarOpen(false);
      });

      expect(result1.current.sidebarOpen).toBe(false);
      expect(result2.current.sidebarOpen).toBe(false);
    });

    it('updates all subscribers when state changes', () => {
      const { result: result1 } = renderHook(() => useAppStore());
      const { result: result2 } = renderHook(() => useAppStore());

      const mockSession: TerminalSession = {
        id: 'test-session',
        name: 'Test Terminal',
        isActive: true,
        lastActivity: new Date(),
      };

      act(() => {
        result1.current.addSession(mockSession);
      });

      expect(result1.current.terminalSessions).toHaveLength(1);
      expect(result2.current.terminalSessions).toHaveLength(1);
      expect(result2.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('maintains referential integrity', () => {
      const { result } = renderHook(() => useAppStore());

      const mockSession: TerminalSession = {
        id: 'test-session',
        name: 'Test Terminal',
        isActive: true,
        lastActivity: new Date(),
      };

      act(() => {
        result.current.addSession(mockSession);
      });

      const sessions1 = result.current.terminalSessions;

      act(() => {
        result.current.setSidebarOpen(false);
      });

      const sessions2 = result.current.terminalSessions;

      // Sessions array should remain the same reference when unrelated state changes
      expect(sessions1).toBe(sessions2);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('handles concurrent session modifications', () => {
      const { result } = renderHook(() => useAppStore());

      const session1: TerminalSession = {
        id: 'session-1',
        name: 'Terminal 1',
        isActive: true,
        lastActivity: new Date(),
      };

      const session2: TerminalSession = {
        id: 'session-2',
        name: 'Terminal 2',
        isActive: true,
        lastActivity: new Date(),
      };

      // Perform multiple operations in quick succession
      act(() => {
        result.current.addSession(session1);
        result.current.addSession(session2);
        result.current.setActiveSession('session-1');
        result.current.updateSession('session-2', { name: 'Updated Terminal 2' });
        result.current.removeSession('session-1');
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0].name).toBe('Updated Terminal 2');
      expect(result.current.activeSessionId).toBe('session-2');
    });

    it('handles invalid session operations gracefully', () => {
      const { result } = renderHook(() => useAppStore());

      // Operations on empty state should not throw
      expect(() => {
        act(() => {
          result.current.removeSession('non-existent');
          result.current.updateSession('non-existent', { name: 'test' });
          result.current.setActiveSession('non-existent');
        });
      }).not.toThrow();

      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBe('non-existent');
    });

    it('handles session with undefined or null properties', () => {
      const { result } = renderHook(() => useAppStore());

      const sessionWithNulls: any = {
        id: 'test-session',
        name: null,
        isActive: undefined,
        lastActivity: null,
      };

      expect(() => {
        act(() => {
          result.current.addSession(sessionWithNulls);
        });
      }).not.toThrow();

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0].id).toBe('test-session');
    });

    it('preserves session order during operations', () => {
      const { result } = renderHook(() => useAppStore());

      const sessions = [
        { id: 'session-1', name: 'Terminal 1', isActive: true, lastActivity: new Date() },
        { id: 'session-2', name: 'Terminal 2', isActive: true, lastActivity: new Date() },
        { id: 'session-3', name: 'Terminal 3', isActive: true, lastActivity: new Date() },
      ];

      act(() => {
        sessions.forEach(session => result.current.addSession(session));
      });

      // Remove middle session
      act(() => {
        result.current.removeSession('session-2');
      });

      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[0].id).toBe('session-1');
      expect(result.current.terminalSessions[1].id).toBe('session-3');
    });
  });
});