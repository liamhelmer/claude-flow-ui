/**
 * Comprehensive unit tests for Zustand store
 * Tests all state management functionality with edge cases
 */

import { act, renderHook } from '@testing-library/react';
import { useAppStore } from '../store';
import type { TerminalSession } from '@/types';

// Mock devtools middleware
jest.mock('zustand/middleware', () => ({
  devtools: (fn: any) => fn,
}));

describe('useAppStore - Comprehensive Tests', () => {
  beforeEach(() => {
    // Reset store before each test
    act(() => {
      useAppStore.setState({
        terminalSessions: [],
        activeSessionId: null,
        sidebarOpen: true,
        loading: false,
        error: null,
      });
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

  describe('Sidebar Management', () => {
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

    it('should set sidebar open state directly', () => {
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
      name: 'Test Terminal 1',
      isActive: true,
      lastActivity: new Date('2025-01-01T00:00:00.000Z'),
    };

    it('should add a new session', () => {
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
        isActive: false,
        lastActivity: new Date('2025-01-01T01:00:00.000Z'),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
      expect(result.current.terminalSessions[1]).toEqual(session2);
    });

    it('should remove a session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      
      act(() => {
        result.current.removeSession('test-session-1');
      });
      
      expect(result.current.terminalSessions).toHaveLength(0);
    });

    it('should handle removing non-existent session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      
      act(() => {
        result.current.removeSession('non-existent-session');
      });
      
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('should update activeSessionId when removing active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session2: TerminalSession = {
        id: 'test-session-2',
        name: 'Test Terminal 2',
        isActive: false,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.addSession(session2);
        result.current.setActiveSession('test-session-1');
      });
      
      expect(result.current.activeSessionId).toBe('test-session-1');
      
      act(() => {
        result.current.removeSession('test-session-1');
      });
      
      expect(result.current.activeSessionId).toBe('test-session-2');
    });

    it('should set activeSessionId to null when removing last session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
        result.current.setActiveSession('test-session-1');
      });
      
      expect(result.current.activeSessionId).toBe('test-session-1');
      
      act(() => {
        result.current.removeSession('test-session-1');
      });
      
      expect(result.current.activeSessionId).toBeNull();
    });

    it('should update session properties', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const updates = {
        name: 'Updated Terminal Name',
        isActive: false,
      };
      
      act(() => {
        result.current.updateSession('test-session-1', updates);
      });
      
      expect(result.current.terminalSessions[0].name).toBe('Updated Terminal Name');
      expect(result.current.terminalSessions[0].isActive).toBe(false);
      expect(result.current.terminalSessions[0].id).toBe('test-session-1');
      expect(result.current.terminalSessions[0].lastActivity).toEqual(mockSession.lastActivity);
    });

    it('should handle updating non-existent session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      const updates = { name: 'Should not update' };
      
      act(() => {
        result.current.updateSession('non-existent-session', updates);
      });
      
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });
  });

  describe('Active Session Management', () => {
    it('should set active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.setActiveSession('test-session-1');
      });
      
      expect(result.current.activeSessionId).toBe('test-session-1');
    });

    it('should clear active session', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.setActiveSession('test-session-1');
      });
      
      expect(result.current.activeSessionId).toBe('test-session-1');
      
      act(() => {
        result.current.setActiveSession(null);
      });
      
      expect(result.current.activeSessionId).toBeNull();
    });
  });

  describe('Loading State Management', () => {
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
  });

  describe('Error State Management', () => {
    it('should set error message', () => {
      const { result } = renderHook(() => useAppStore());
      
      const errorMessage = 'Test error message';
      
      act(() => {
        result.current.setError(errorMessage);
      });
      
      expect(result.current.error).toBe(errorMessage);
    });

    it('should clear error message', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.setError('Error message');
      });
      
      expect(result.current.error).toBe('Error message');
      
      act(() => {
        result.current.setError(null);
      });
      
      expect(result.current.error).toBeNull();
    });
  });

  describe('Session Creation', () => {
    it('should create new session with generated ID', () => {
      const { result } = renderHook(() => useAppStore());
      
      const mockDate = new Date('2025-01-01T00:00:00.000Z');
      const mockRandom = jest.spyOn(Math, 'random').mockReturnValue(0.123456789);
      const mockNow = jest.spyOn(Date, 'now').mockReturnValue(mockDate.getTime());
      
      let sessionId: string;
      
      act(() => {
        sessionId = result.current.createNewSession();
      });
      
      expect(sessionId!).toBe('session-1735689600000-123456789');
      expect(result.current.terminalSessions).toHaveLength(1);
      expect(result.current.terminalSessions[0].id).toBe(sessionId!);
      expect(result.current.terminalSessions[0].name).toBe('Terminal 1');
      expect(result.current.terminalSessions[0].isActive).toBe(true);
      expect(result.current.activeSessionId).toBe(sessionId!);
      
      mockRandom.mockRestore();
      mockNow.mockRestore();
    });

    it('should create session with incremented name', () => {
      const { result } = renderHook(() => useAppStore());
      
      const mockSession: TerminalSession = {
        id: 'existing-session',
        name: 'Existing Terminal',
        isActive: false,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession);
      });
      
      let sessionId: string;
      
      act(() => {
        sessionId = result.current.createNewSession();
      });
      
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2');
      expect(result.current.activeSessionId).toBe(sessionId!);
    });
  });

  describe('Clear Sessions', () => {
    it('should clear all sessions', () => {
      const { result } = renderHook(() => useAppStore());
      
      const mockSession1: TerminalSession = {
        id: 'session-1',
        name: 'Terminal 1',
        isActive: true,
        lastActivity: new Date(),
      };
      
      const mockSession2: TerminalSession = {
        id: 'session-2',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date(),
      };
      
      act(() => {
        result.current.addSession(mockSession1);
        result.current.addSession(mockSession2);
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

  describe('State Persistence', () => {
    it('should maintain state consistency across multiple operations', () => {
      const { result } = renderHook(() => useAppStore());
      
      const session1: TerminalSession = {
        id: 'session-1',
        name: 'Terminal 1',
        isActive: true,
        lastActivity: new Date('2025-01-01T00:00:00.000Z'),
      };
      
      const session2: TerminalSession = {
        id: 'session-2',
        name: 'Terminal 2',
        isActive: false,
        lastActivity: new Date('2025-01-01T01:00:00.000Z'),
      };
      
      act(() => {
        // Add sessions
        result.current.addSession(session1);
        result.current.addSession(session2);
        
        // Set active session
        result.current.setActiveSession('session-2');
        
        // Update session
        result.current.updateSession('session-1', { name: 'Updated Terminal 1' });
        
        // Set loading and error states
        result.current.setLoading(true);
        result.current.setError('Test error');
        
        // Toggle sidebar
        result.current.toggleSidebar();
      });
      
      // Verify final state
      expect(result.current.terminalSessions).toHaveLength(2);
      expect(result.current.terminalSessions[0].name).toBe('Updated Terminal 1');
      expect(result.current.terminalSessions[1].name).toBe('Terminal 2');
      expect(result.current.activeSessionId).toBe('session-2');
      expect(result.current.loading).toBe(true);
      expect(result.current.error).toBe('Test error');
      expect(result.current.sidebarOpen).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty session updates gracefully', () => {
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
      
      act(() => {
        result.current.updateSession('test-session', {});
      });
      
      expect(result.current.terminalSessions[0]).toEqual(mockSession);
    });

    it('should handle null and undefined values correctly', () => {
      const { result } = renderHook(() => useAppStore());
      
      act(() => {
        result.current.setActiveSession(null);
        result.current.setError(null);
        result.current.setLoading(false);
      });
      
      expect(result.current.activeSessionId).toBeNull();
      expect(result.current.error).toBeNull();
      expect(result.current.loading).toBe(false);
    });
  });
});