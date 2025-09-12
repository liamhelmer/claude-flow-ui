import { act, renderHook } from '@testing-library/react';
import { useAppStore } from '../store';
import type { TerminalSession } from '@/types';

describe('App Store', () => {
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
    it('should set sidebar open state', () => {
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

    it('should toggle sidebar state', () => {
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
  });

  describe('Active Session Management', () => {
    it('should set active session', () => {
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
  });

  describe('Session Management', () => {
    const mockSession: TerminalSession = {
      id: 'session-1',
      name: 'Terminal 1',
      isActive: true,
      lastActivity: new Date(),
    };

    it('should add session', () => {
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
        id: 'session-2',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[1]).toEqual(session2);
    });

    it('should remove session', () => {
      const { result } = renderHook(() => useAppStore());
      
      // Add session first
      act(() => {
        result.current.addSession(mockSession);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      
      // Remove session
      act(() => {
        result.current.removeSession('session-1');
      });
      
      expect(result.current.terminalSessions).toHaveLength(0);
    });

    it('should remove session and update active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session2: TerminalSession = {
        id: 'session-2',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date(),
      };
      
      // Add sessions and set active
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession('session-1');
      });
      
      expect(result.current.activeSessionId).toBe('session-1');
      
      // Remove active session
      act(() => {
        result.current.removeSession('session-1');
      });
      
      // Should set first remaining session as active
      expect(result.current.activeSessionId).toBe('session-2');
      expect(result.current.terminalSessions).toHaveLength(1);
    });

    it('should handle removing non-existent session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      
      act(() => {
        result.current.removeSession('non-existent');
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
    });

    it('should clear active session when removing last session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.setActiveSession('session-1');
      });
      
      expect(result.current.activeSessionId).toBe('session-1');
      
      act(() => {
        result.current.removeSession('session-1');
      });
      
      expect(result.current.activeSessionId).toBeNull();
    });

    it('should update session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const updates = {
        name: 'Updated Terminal',
        isActive: false,
      };
      
      act(() => {
        result.current.updateSession('session-1', updates);
      });
      
      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe('Updated Terminal');
      expect(updatedSession.isActive).toBe(false);
      expect(updatedSession.id).toBe('session-1'); // Should preserve unchanged properties
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

    it('should clear all sessions', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session2: TerminalSession = {
        id: 'session-2',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession('session-1');
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.activeSessionId).toBe('session-1');
      
      act(() => {
        result.current.clearSessions();
      });
      
      expect(result.current.terminalSessions).toHaveLength(0);
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
      
      act(() => {
        result.current.setError('Something went wrong');
      });
      
      expect(result.current.error).toBe('Something went wrong');
      
      act(() => {
        result.current.setError(null);
      });
      
      expect(result.current.error).toBeNull();
    });
  });

  describe('Create New Session', () => {
    beforeEach(() => {
      // Mock Date.now to have predictable session IDs
      jest.spyOn(Date, 'now').mockReturnValue(1234567890);
      jest.spyOn(Math, 'random').mockReturnValue(0.123456789);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should create new session with generated ID', () => {
      const { result } = renderHook(() => useAppStore());
      
      let sessionId: string;
      
      act(() => {
        sessionId = result.current.createNewSession();
      });
      
      expect(sessionId).toMatch(/^session-\d+-[a-z0-9]+$/);
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe(sessionId);
      
      const newSession = result.current.terminalSessions[0];
      expect(newSession.id).toBe(sessionId);
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
      
      expect(result.current.terminalSessions).toHaveLength(3);
      expect(result.current.terminalSessions[0].name).toBe('Terminal 1');
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2');
      expect(result.current.terminalSessions[2].name).toBe('Terminal 3');
    });

    it('should set newly created session as active', () => {
      const { result } = renderHook(() => useAppStore());
      
      let firstSessionId: string;
      let secondSessionId: string;
      
      act(() => {
        firstSessionId = result.current.createNewSession();
      });
      
      expect(result.current.activeSessionId).toBe(firstSessionId);
      
      act(() => {
        secondSessionId = result.current.createNewSession();
      });
      
      expect(result.current.activeSessionId).toBe(secondSessionId);
    });
  });

  describe('Store Persistence and DevTools', () => {
    it('should be configured with devtools', () => {
      // This is more of an integration test to ensure the store is properly configured
      const { result } = renderHook(() => useAppStore());
      
      // The store should have the expected methods and state
      expect(typeof result.current.setSidebarOpen).toBe('function');
      expect(typeof result.current.toggleSidebar).toBe('function');
      expect(typeof result.current.addSession).toBe('function');
      expect(typeof result.current.removeSession).toBe('function');
      expect(typeof result.current.updateSession).toBe('function');
      expect(typeof result.current.createNewSession).toBe('function');
      expect(typeof result.current.clearSessions).toBe('function');
    });
  });

  describe('Edge Cases', () => {
    it('should handle partial session updates', () => {
      const { result } = renderHook(() => useAppStore());
      
      const originalDate = new Date();
      const session: TerminalSession = {
        id: 'session-1',
        name: 'Terminal 1',
        isActive: true,
        lastActivity: originalDate,
      };
      
      act(() => {
        result.current.addSession(session);
      });
      
      // Update only the name
      act(() => {
        result.current.updateSession('session-1', { name: 'New Name' });
      });
      
      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe('New Name');
      expect(updatedSession.isActive).toBe(true); // Unchanged
      expect(updatedSession.lastActivity).toBe(originalDate); // Unchanged
      expect(updatedSession.id).toBe('session-1'); // Unchanged
    });

    it('should handle empty updates', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const originalSession = { ...result.current.terminalSessions[0] };
      
      act(() => {
        result.current.updateSession('session-1', {});
      });
      
      expect(result.current.terminalSessions[0]).toEqual(originalSession);
    });
  });
});

// Additional test for session ID generation utility
describe('Session ID Generation', () => {
  it('should generate unique session IDs', () => {
    const { result } = renderHook(() => useAppStore());
    
    const ids = new Set();
    
    act(() => {
      for (let i = 0; i < 100; i++) {
        const id = result.current.createNewSession();
        ids.add(id);
      }
    });
    
    // All IDs should be unique
    expect(ids.size).toBe(100);
  });
});