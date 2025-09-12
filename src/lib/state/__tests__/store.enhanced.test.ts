import { act, renderHook } from '@testing-library/react';
import { useAppStore } from '../store';
import type { TerminalSession } from '@/types';

// Mock devtools for testing
jest.mock('zustand/middleware', () => ({
  devtools: (fn: any) => fn,
}));

describe('useAppStore', () => {
  let store: ReturnType<typeof useAppStore>;

  beforeEach(() => {
    // Reset store to initial state
    const { result } = renderHook(() => useAppStore());
    store = result.current;
    
    // Clear all sessions to start fresh
    act(() => {
      store.clearSessions();
      store.setSidebarOpen(true);
      store.setError(null);
      store.setLoading(false);
    });
  });

  describe('initial state', () => {
    it('should have correct initial state', () => {
      const { result } = renderHook(() => useAppStore());
      const state = result.current;

      expect(state.terminalSessions).toEqual([]);
      expect(state.activeSessionId).toBeNull();
      expect(state.sidebarOpen).toBe(true);
      expect(state.loading).toBe(false);
      expect(state.error).toBeNull();
    });
  });

  describe('sidebar management', () => {
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

    it('should handle multiple rapid toggles', () => {
      const { result } = renderHook(() => useAppStore());

      const initialState = result.current.sidebarOpen;

      act(() => {
        result.current.toggleSidebar();
        result.current.toggleSidebar();
        result.current.toggleSidebar();
      });

      expect(result.current.sidebarOpen).toBe(!initialState);
    });
  });

  describe('session management', () => {
    const mockSession: TerminalSession = {
      id: 'session-123',
      name: 'Terminal 1',
      isActive: true,
      lastActivity: new Date('2023-01-01'),
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
        id: 'session-456',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date('2023-01-02'),
      };

      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
      });

      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions).toEqual([mockSession, session2]);
    });

    it('should set active session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setActiveSession('session-123');
      });

      expect(result.current.activeSessionId).toBe('session-123');
    });

    it('should clear active session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setActiveSession('session-123');
        result.current.setActiveSession(null);
      });

      expect(result.current.activeSessionId).toBeNull();
    });

    it('should remove a session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
        result.current.setActiveSession(mockSession.id);
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe(mockSession.id);

      act(() => {
        result.current.removeSession(mockSession.id);
      });

      expect(result.current.terminalSessions).toHaveLength(0);
      expect(result.current.activeSessionId).toBeNull();
    });

    it('should remove session and set new active session', () => {
      const { result } = renderHook(() => useAppStore());

      const session2: TerminalSession = {
        id: 'session-456',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date(),
      };

      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession(mockSession.id);
      });

      act(() => {
        result.current.removeSession(mockSession.id);
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0]).toEqual(session2);
      expect(result.current.activeSessionId).toBe(session2.id);
    });

    it('should handle removing non-existent session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      const initialLength = result.current.terminalSessions.length;

      act(() => {
        result.current.removeSession('non-existent');
      });

      expect(result.current.terminalSessions).toHaveLength(initialLength);
    });

    it('should preserve active session when removing different session', () => {
      const { result } = renderHook(() => useAppStore());

      const session2: TerminalSession = {
        id: 'session-456',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date(),
      };

      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession(mockSession.id);
      });

      act(() => {
        result.current.removeSession(session2.id);
      });

      expect(result.current.activeSessionId).toBe(mockSession.id);
    });

    it('should update session properties', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      const updates = {
        name: 'Updated Terminal',
        isActive: false,
        lastActivity: new Date('2023-12-25'),
      };

      act(() => {
        result.current.updateSession(mockSession.id, updates);
      });

      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe(updates.name);
      expect(updatedSession.isActive).toBe(updates.isActive);
      expect(updatedSession.lastActivity).toEqual(updates.lastActivity);
      expect(updatedSession.id).toBe(mockSession.id); // ID should remain unchanged
    });

    it('should handle partial updates', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      act(() => {
        result.current.updateSession(mockSession.id, { name: 'Partially Updated' });
      });

      const updatedSession = result.current.terminalSessions[0];
      expect(updatedSession.name).toBe('Partially Updated');
      expect(updatedSession.isActive).toBe(mockSession.isActive); // Should remain unchanged
      expect(updatedSession.lastActivity).toEqual(mockSession.lastActivity); // Should remain unchanged
    });

    it('should handle updating non-existent session', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.addSession(mockSession);
      });

      const originalSession = { ...result.current.terminalSessions[0] };

      act(() => {
        result.current.updateSession('non-existent', { name: 'Updated' });
      });

      expect(result.current.terminalSessions[0]).toEqual(originalSession);
    });

    it('should clear all sessions', () => {
      const { result } = renderHook(() => useAppStore());

      const session2: TerminalSession = {
        id: 'session-456',
        name: 'Terminal 2',
        isActive: false,
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
      expect(result.current.activeSessionId).toBeNull();
    });
  });

  describe('session creation', () => {
    it('should create new session with generated ID', () => {
      const { result } = renderHook(() => useAppStore());

      let sessionId: string;
      act(() => {
        sessionId = result.current.createNewSession();
      });

      expect(sessionId!).toMatch(/^session-\d+-[a-z0-9]+$/);
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.activeSessionId).toBe(sessionId!);

      const session = result.current.terminalSessions[0];
      expect(session.id).toBe(sessionId!);
      expect(session.name).toBe('Terminal 1');
      expect(session.isActive).toBe(true);
      expect(session.lastActivity).toBeInstanceOf(Date);
    });

    it('should create multiple sessions with incremental names', () => {
      const { result } = renderHook(() => useAppStore());

      let sessionId1: string;
      let sessionId2: string;
      let sessionId3: string;

      act(() => {
        sessionId1 = result.current.createNewSession();
        sessionId2 = result.current.createNewSession();
        sessionId3 = result.current.createNewSession();
      });

      expect(result.current.terminalSessions).toHaveLength(3);
      
      const sessions = result.current.terminalSessions;
      expect(sessions[0].name).toBe('Terminal 1');
      expect(sessions[1].name).toBe('Terminal 2');
      expect(sessions[2].name).toBe('Terminal 3');
      
      expect(result.current.activeSessionId).toBe(sessionId3!);
    });

    it('should create session with unique IDs', () => {
      const { result } = renderHook(() => useAppStore());

      const sessionIds: string[] = [];

      act(() => {
        for (let i = 0; i < 5; i++) {
          sessionIds.push(result.current.createNewSession());
        }
      });

      const uniqueIds = new Set(sessionIds);
      expect(uniqueIds.size).toBe(5);
    });

    it('should handle rapid session creation', () => {
      const { result } = renderHook(() => useAppStore());

      const sessionIds: string[] = [];

      act(() => {
        // Create many sessions in rapid succession
        for (let i = 0; i < 10; i++) {
          sessionIds.push(result.current.createNewSession());
        }
      });

      expect(result.current.terminalSessions).toHaveLength(10);
      expect(new Set(sessionIds).size).toBe(10); // All IDs should be unique
      expect(result.current.activeSessionId).toBe(sessionIds[sessionIds.length - 1]);
    });
  });

  describe('loading and error state', () => {
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
        result.current.setError('Connection failed');
      });

      expect(result.current.error).toBe('Connection failed');

      act(() => {
        result.current.setError(null);
      });

      expect(result.current.error).toBeNull();
    });

    it('should handle complex error objects', () => {
      const { result } = renderHook(() => useAppStore());

      const complexError = 'Network timeout after 30 seconds';

      act(() => {
        result.current.setError(complexError);
      });

      expect(result.current.error).toBe(complexError);
    });

    it('should handle simultaneous loading and error states', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setLoading(true);
        result.current.setError('Something went wrong');
      });

      expect(result.current.loading).toBe(true);
      expect(result.current.error).toBe('Something went wrong');

      act(() => {
        result.current.setLoading(false);
        result.current.setError(null);
      });

      expect(result.current.loading).toBe(false);
      expect(result.current.error).toBeNull();
    });
  });

  describe('complex state interactions', () => {
    it('should handle session management with loading states', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setLoading(true);
        result.current.createNewSession();
        result.current.setLoading(false);
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.loading).toBe(false);
    });

    it('should handle error states during session operations', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.createNewSession();
        result.current.setError('Session creation failed');
      });

      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.error).toBe('Session creation failed');
    });

    it('should maintain consistency during batch operations', () => {
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
        isActive: false,
        lastActivity: new Date(),
      };

      act(() => {
        result.current.addSession(session1);
        result.current.addSession(session2);
        result.current.setActiveSession(session1.id);
        result.current.updateSession(session2.id, { name: 'Updated Terminal 2' });
        result.current.setSidebarOpen(false);
      });

      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.activeSessionId).toBe(session1.id);
      expect(result.current.terminalSessions[1].name).toBe('Updated Terminal 2');
      expect(result.current.sidebarOpen).toBe(false);
    });
  });

  describe('edge cases and error scenarios', () => {
    it('should handle malformed session objects', () => {
      const { result } = renderHook(() => useAppStore());

      const malformedSession = {
        id: 'test',
        name: 'Test',
        // Missing isActive and lastActivity
      } as TerminalSession;

      expect(() => {
        act(() => {
          result.current.addSession(malformedSession);
        });
      }).not.toThrow();

      expect(result.current.terminalSessions).toHaveLength(1);
    });

    it('should handle empty string session IDs', () => {
      const { result } = renderHook(() => useAppStore());

      act(() => {
        result.current.setActiveSession('');
      });

      expect(result.current.activeSessionId).toBe('');
    });

    it('should handle null values gracefully', () => {
      const { result } = renderHook(() => useAppStore());

      expect(() => {
        act(() => {
          result.current.updateSession('test', null as any);
        });
      }).not.toThrow();
    });

    it('should handle concurrent modifications', async () => {
      const { result } = renderHook(() => useAppStore());

      const promises = Array.from({ length: 5 }, (_, i) => 
        new Promise<void>((resolve) => {
          act(() => {
            const sessionId = result.current.createNewSession();
            result.current.updateSession(sessionId, { name: `Concurrent ${i}` });
            resolve();
          });
        })
      );

      await Promise.all(promises);

      expect(result.current.terminalSessions).toHaveLength(5);
      result.current.terminalSessions.forEach((session, index) => {
        expect(session.name).toContain('Concurrent');
      });
    });
  });

  describe('performance and memory', () => {
    it('should handle large numbers of sessions', () => {
      const { result } = renderHook(() => useAppStore());

      const sessionCount = 1000;

      act(() => {
        for (let i = 0; i < sessionCount; i++) {
          result.current.createNewSession();
        }
      });

      expect(result.current.terminalSessions).toHaveLength(sessionCount);
      expect(result.current.terminalSessions[sessionCount - 1].name).toBe(`Terminal ${sessionCount}`);
    });

    it('should handle frequent updates efficiently', () => {
      const { result } = renderHook(() => useAppStore());

      const sessionId = result.current.createNewSession();

      act(() => {
        for (let i = 0; i < 100; i++) {
          result.current.updateSession(sessionId, { 
            name: `Updated ${i}`,
            lastActivity: new Date(),
          });
        }
      });

      expect(result.current.terminalSessions[0].name).toBe('Updated 99');
    });
  });
});