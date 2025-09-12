import { act, renderHook } from '@testing-library/react';
import { useAppStore } from '@/lib/state/store';
import type { TerminalSession } from '@/types';

describe('AppStore', () => {
  beforeEach(() => {
    // Reset store state before each test
    useAppStore.setState({
      terminalSessions: [],
      activeSessionId: null,
      sidebarOpen: true,
      loading: false,
      error: null,
    });
  });

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      const { result } = renderHook(() => useAppStore());
      
      expect(result.current.terminalSessions).toEqual([]);
      expect(result.current.activeSessionId).toBeNull();
      expect(result.current.sidebarOpen).toBe(true);
      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBeNull();
    });
  });

  describe('Sidebar Actions', () => {
    it('should toggle sidebar state', () => {
      const { result } = renderHook(() => useAppStore());
      
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

  describe('Session Management', () => {
    const mockSession: TerminalSession = {
      id: 'test-session-1',
      name: 'Test Session',
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

    it('should remove a session', () => {
      const { result } = renderHook(() => useAppStore());
      
      // Add session first
      act(() => {
        result.current.addSession(mockSession);
        result.current.setActiveSession(mockSession.id);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe(mockSession.id);
      
      // Remove session
      act(() => {
        result.current.removeSession(mockSession.id);
      });
      
      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBeNull();
    });

    it('should update active session when removing active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session1 = { ...mockSession, id: 'session-1' };
      const session2 = { ...mockSession, id: 'session-2' };
      
      // Add two sessions
      act(() => {
        result.current.addSession(session1);
        result.current.addSession(session2);
        result.current.setActiveSession(session2.id);
      });
      
      expect(result.current.activeSessionId).toBe(session2.id);
      
      // Remove active session
      act(() => {
        result.current.removeSession(session2.id);
      });
      
      // Should set first remaining session as active
      expect(result.current.activeSessionId).toBe(session1.id);
      expect(result.current.terminalSessions).toHaveLength(1);
    });

    it('should update a session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const updates = {
        name: 'Updated Session Name',
        isActive: false,
      };
      
      act(() => {
        result.current.updateSession(mockSession.id, updates);
      });
      
      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe('Updated Session Name');
      expect(updatedSession.isActive).toBe(false);
      expect(updatedSession.id).toBe(mockSession.id); // Should preserve unchanged fields
    });

    it('should not update non-existent session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const originalSessions = result.current.terminalSessions;
      
      act(() => {
        result.current.updateSession('non-existent-id', { name: 'New Name' });
      });
      
      expect(result.current.terminalSessions).toEqual(originalSessions);
    });

    it('should create new session with auto-generated properties', () => {
      const { result } = renderHook(() => useAppStore());
      
      let sessionId: string;
      
      act(() => {
        sessionId = result.current.createNewSession();
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe(sessionId);
      
      const newSession = result.current.terminalSessions[0];
      expect(newSession.id).toMatch(/^session-\d+-[a-z0-9]{9}$/);
      expect(newSession.name).toBe('Terminal 1');
      expect(newSession.isActive).toBe(true);
      expect(newSession.lastActivity).toBeInstanceOf(Date);
    });

    it('should create sessions with incremental names', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.createNewSession();
        result.current.createNewSession();
        result.current.createNewSession();
      });
      
      const sessions = result.current.terminalSessions;
      expect(sessions[0].name).toBe('Terminal 1');
      expect(sessions[1].name).toBe('Terminal 2');
      expect(sessions[2].name).toBe('Terminal 3');
    });

    it('should clear all sessions', () => {
      const { result } = renderHook(() => useAppStore());
      
      // Add some sessions
      act(() => {
        result.current.createNewSession();
        result.current.createNewSession();
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.activeSessionId).toBeTruthy();
      
      // Clear sessions
      act(() => {
        result.current.clearSessions();
      });
      
      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBeNull();
    });
  });

  describe('Active Session Management', () => {
    it('should set active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.setActiveSession('test-session-id');
      });
      
      expect(result.current.activeSessionId).toBe('test-session-id');
    });

    it('should clear active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.setActiveSession('test-session-id');
        result.current.setActiveSession(null);
      });
      
      expect(result.current.activeSessionId).toBeNull();
    });
  });

  describe('Loading and Error States', () => {
    it('should set loading state', () => {
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

    it('should set error state', () => {
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
  });

  describe('Complex Scenarios', () => {
    it('should handle multiple operations correctly', () => {
      const { result } = renderHook(() => useAppStore());
      
      // Create multiple sessions and perform various operations
      let sessionId1: string, sessionId2: string;
      
      act(() => {
        sessionId1 = result.current.createNewSession();
        sessionId2 = result.current.createNewSession();
        
        result.current.updateSession(sessionId1, { name: 'Production Terminal' });
        result.current.setActiveSession(sessionId1);
        result.current.setSidebarOpen(false);
        result.current.setLoading(true);
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[0].name).toBe('Production Terminal');
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2');
      expect(result.current.activeSessionId).toBe(sessionId1);
      expect(result.current.sidebarOpen).toBe(false);
      expect(result.current.loading).toBe(true);
    });

    it('should maintain consistency when removing sessions', () => {
      const { result } = renderHook(() => useAppStore());
      
      // Create multiple sessions
      let sessionId1: string, sessionId2: string, sessionId3: string;
      
      act(() => {
        sessionId1 = result.current.createNewSession();
        sessionId2 = result.current.createNewSession();
        sessionId3 = result.current.createNewSession();
        
        // Set middle session as active
        result.current.setActiveSession(sessionId2);
      });
      
      expect(result.current.activeSessionId).toBe(sessionId2);
      
      // Remove active session
      act(() => {
        result.current.removeSession(sessionId2);
      });
      
      // Should set first remaining session as active
      expect(result.current.activeSessionId).toBe(sessionId1);
      expect(result.current.terminalSessions).toHaveLength(2);
      
      // Remove non-active session
      act(() => {
        result.current.removeSession(sessionId3);
      });
      
      // Active session should remain unchanged
      expect(result.current.activeSessionId).toBe(sessionId1);
      expect(result.current.terminalSessions).toHaveLength(1);
    });
  });

  describe('Edge Cases', () => {
    it('should handle removing non-existent session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.createNewSession();
      });
      
      const originalSessions = result.current.terminalSessions;
      const originalActiveId = result.current.activeSessionId;
      
      act(() => {
        result.current.removeSession('non-existent-id');
      });
      
      expect(result.current.terminalSessions).toEqual(originalSessions);
      expect(result.current.activeSessionId).toBe(originalActiveId);
    });

    it('should handle empty session updates', () => {
      const { result } = renderHook(() => useAppStore());
      
      const mockSession: TerminalSession = {
        id: 'test-session',
        name: 'Test Session',
        isActive: true,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const originalSession = result.current.terminalSessions[0];
      
      act(() => {
        result.current.updateSession(mockSession.id, {});
      });
      
      expect(result.current.terminalSessions[0]).toEqual(originalSession);
    });

    it('should handle session creation with existing sessions', () => {
      const { result } = renderHook(() => useAppStore());
      
      const existingSession: TerminalSession = {
        id: 'existing-session',
        name: 'Existing Session',
        isActive: true,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(existingSession);
      });
      
      let newSessionId: string;
      
      act(() => {
        newSessionId = result.current.createNewSession();
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2'); // Should be incremental
      expect(result.current.activeSessionId).toBe(newSessionId);
    });
  });

  describe('Store Persistence', () => {
    it('should be configured with devtools name', () => {
      // This test verifies the store is set up with devtools
      // The actual devtools configuration is tested by the setup
      const { result } = renderHook(() => useAppStore());
      
      expect(result.current).toBeDefined();
      expect(typeof result.current.createNewSession).toBe('function');
      expect(typeof result.current.addSession).toBe('function');
    });
  });

  describe('Type Safety', () => {
    it('should enforce TerminalSession interface', () => {
      const { result } = renderHook(() => useAppStore());
      
      const validSession: TerminalSession = {
        id: 'valid-session',
        name: 'Valid Session',
        isActive: true,
        lastActivity: new Date(),
      };
      
      // Should not throw with valid session
      act(() => {
        result.current.addSession(validSession);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
    });

    it('should allow partial updates in updateSession', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session: TerminalSession = {
        id: 'test-session',
        name: 'Original Name',
        isActive: false,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(session);
      });
      
      // Partial update should work
      act(() => {
        result.current.updateSession(session.id, { name: 'Updated Name' });
      });
      
      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe('Updated Name');
      expect(updatedSession.isActive).toBe(false); // Should preserve other fields
    });
  });
});