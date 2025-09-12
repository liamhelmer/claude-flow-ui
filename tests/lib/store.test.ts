import { act, renderHook } from '@testing-library/react';
import { useAppStore } from '@/lib/state/store';
import type { TerminalSession } from '@/types';

// Mock zustand devtools
jest.mock('zustand/middleware', () => ({
  devtools: (fn: any) => fn,
}));

describe('useAppStore', () => {
  beforeEach(() => {
    // Reset store to initial state before each test
    const { result } = renderHook(() => useAppStore());
    act(() => {
      result.current.clearSessions();
      result.current.setSidebarOpen(true);
      result.current.setLoading(false);
      result.current.setError(null);
    });
  });

  describe('initial state', () => {
    it('should have correct initial values', () => {
      const { result } = renderHook(() => useAppStore());
      
      expect(result.current.terminalSessions).toEqual([]);
      expect(result.current.activeSessionId).toBe(null);
      expect(result.current.sidebarOpen).toBe(true);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBe(null);
    });
  });

  describe('sidebar management', () => {
    it('should toggle sidebar state', () => {
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

    it('should set sidebar state directly', () => {
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
  });

  describe('session management', () => {
    const mockSession: TerminalSession = {
      id: 'test-session-1',
      name: 'Test Terminal 1',
      isActive: true,
      lastActivity: new Date(),
    };

    it('should add a session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('should add multiple sessions', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session2: TerminalSession = {
        id: 'test-session-2',
        name: 'Test Terminal 2',
        isActive: true,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
      expect(result.current.terminalSessions[1]).toEqual(session2);
    });

    it('should set active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.setActiveSession(mockSession.id);
      });
      
      expect(result.current.activeSessionId).toBe(mockSession.id);
    });

    it('should update session', () => {
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
      
      expect(result.current.terminalSessions[0]).toEqual({
        ...mockSession,
        ...updates,
      });
    });

    it('should not update non-existent session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const originalSessions = result.current.terminalSessions;
      
      act(() => {
        result.current.updateSession('non-existent', { name: 'Updated' });
      });
      
      expect(result.current.terminalSessions).toEqual(originalSessions);
    });

    it('should remove session', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session2: TerminalSession = {
        id: 'test-session-2',
        name: 'Test Terminal 2',
        isActive: true,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession(mockSession.id);
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.activeSessionId).toBe(mockSession.id);
      
      act(() => {
        result.current.removeSession(mockSession.id);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0]).toEqual(session2);
      expect(result.current.activeSessionId).toBe(session2.id); // Should switch to remaining session
    });

    it('should clear active session when removing the active session and no other sessions exist', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.setActiveSession(mockSession.id);
      });
      
      expect(result.current.activeSessionId).toBe(mockSession.id);
      
      act(() => {
        result.current.removeSession(mockSession.id);
      });
      
      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBe(null);
    });

    it('should not change active session when removing non-active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session2: TerminalSession = {
        id: 'test-session-2',
        name: 'Test Terminal 2',
        isActive: true,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession(mockSession.id);
      });
      
      expect(result.current.activeSessionId).toBe(mockSession.id);
      
      act(() => {
        result.current.removeSession(session2.id);
      });
      
      expect(result.current.activeSessionId).toBe(mockSession.id); // Should remain unchanged
      expect(result.current.terminalSessions).toHaveLength(1);
    });

    it('should create new session with generated ID', () => {
      const { result } = renderHook(() => useAppStore());
      
      let sessionId: string;
      act(() => {
        sessionId = result.current.createNewSession();
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe(sessionId!);
      
      const session = result.current.terminalSessions[0];
      expect(session.id).toBe(sessionId!);
      expect(session.name).toBe('Terminal 1');
      expect(session.isActive).toBe(true);
      expect(session.lastActivity).toBeInstanceOf(Date);
    });

    it('should create multiple sessions with incremented names', () => {
      const { result } = renderHook(() => useAppStore());
      
      let sessionId1: string, sessionId2: string;
      act(() => {
        sessionId1 = result.current.createNewSession();
        sessionId2 = result.current.createNewSession();
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[0].name).toBe('Terminal 1');
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2');
      expect(result.current.activeSessionId).toBe(sessionId2!); // Should be latest created
    });

    it('should clear all sessions', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session2: TerminalSession = {
        id: 'test-session-2',
        name: 'Test Terminal 2',
        isActive: true,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession(mockSession.id);
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.activeSessionId).toBe(mockSession.id);
      
      act(() => {
        result.current.clearSessions();
      });
      
      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBe(null);
    });
  });

  describe('loading and error states', () => {
    it('should set loading state', () => {
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

    it('should set error state', () => {
      const { result } = renderHook(() => useAppStore());
      
      expect(result.current.error).toBe(null);
      
      act(() => {
        result.current.setError('Test error message');
      });
      
      expect(result.current.error).toBe('Test error message');
      
      act(() => {
        result.current.setError(null);
      });
      
      expect(result.current.error).toBe(null);
    });
  });

  describe('session ID generation', () => {
    it('should generate unique session IDs', () => {
      const { result } = renderHook(() => useAppStore());
      
      let sessionId1: string, sessionId2: string;
      act(() => {
        sessionId1 = result.current.createNewSession();
        sessionId2 = result.current.createNewSession();
      });
      
      expect(sessionId1).not.toBe(sessionId2);
      expect(sessionId1).toMatch(/^session-\d+-[a-z0-9]+$/);
      expect(sessionId2).toMatch(/^session-\d+-[a-z0-9]+$/);
    });
  });

  describe('concurrent operations', () => {
    it('should handle concurrent session operations', () => {
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
      
      act(() => {
        // Perform multiple operations in quick succession
        result.current.addSession(session1);
        result.current.addSession(session2);
        result.current.setActiveSession(session1.id);
        result.current.updateSession(session2.id, { name: 'Updated Terminal 2' });
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.activeSessionId).toBe(session1.id);
      expect(result.current.terminalSessions[1].name).toBe('Updated Terminal 2');
    });
  });

  describe('edge cases', () => {
    it('should handle removing non-existent session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const originalState = {
        sessions: result.current.terminalSessions,
        activeId: result.current.activeSessionId,
      };
      
      act(() => {
        result.current.removeSession('non-existent-id');
      });
      
      expect(result.current.terminalSessions).toEqual(originalState.sessions);
      expect(result.current.activeSessionId).toBe(originalState.activeId);
    });

    it('should handle setting active session to non-existent ID', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.setActiveSession('non-existent-id');
      });
      
      expect(result.current.activeSessionId).toBe('non-existent-id'); // Store allows this
    });

    it('should handle empty operations gracefully', () => {
      const { result } = renderHook(() => useAppStore());
      
      // These should not throw errors
      act(() => {
        result.current.removeSession('');
        result.current.updateSession('', {});
        result.current.setActiveSession('');
        result.current.setError('');
      });
      
      expect(result.current.terminalSessions).toEqual([]);
      expect(result.current.activeSessionId).toBe('');
      expect(result.current.error).toBe('');
    });
  });
});